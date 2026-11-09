from __future__ import annotations

import asyncio
import hashlib

import httpx
import pytest

from app.services.ai_router import AIRouter, OutputWithheldError
from backend.coordination.authorization_proof import issue_gate_authorization_proof
from backend.coordination.evidence_adapter import SCARLedgerSink
from backend.coordination.dual_gate_path import EvidenceAppendReceipt
from sovereign.scar.ledger import SCARLedger
from sovereign_core.heavy_judge import HeavyJudge
from sovereign_core.judge_composition import ComposedHeavyJudge


KEY = b"async-router-test-verification-key"
OWNER = "owner-420"
TASK = "task-async-1"
SCOPE = ("provider:remote",)


class Root:
    def sign(self, payload: bytes):
        class Signature:
            def __init__(self, value: bytes):
                self.signature = value
        return Signature(hashlib.sha256(payload).digest())


class ModelBackend:
    model_id = "fixture-heavy-judge"

    def __init__(self, action: str = "PASS", *, memory_loaded: bool = False,
                 network_accessed: bool = False):
        self.action = action
        self.memory_loaded = memory_loaded
        self.network_accessed = network_accessed

    def evaluate(self, candidate: str, context: str):
        return {
            "action": self.action,
            "reason": "fixture",
            "memory_loaded": self.memory_loaded,
            "network_accessed": self.network_accessed,
        }


class Provider:
    def __init__(self, result=None, error=None):
        self.result = result or {"text": "Rayleigh scattering explains the blue sky."}
        self.error = error
        self.calls = 0

    async def chat(self, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        return dict(self.result)


def proof(*, task_id: str = TASK, owner_id: str = OWNER, scope=SCOPE):
    return issue_gate_authorization_proof(
        proof_id="gate-proof-async-test",
        owner_id=owner_id,
        task_id=task_id,
        scope=scope,
        decision="OWNER_AUTHORIZED",
        policy_hash="sha256:test-policy",
        issued_at=100,
        expires_at=4_000_000_000,
        secret=KEY,
    )


def make_router(providers, *, action="PASS", evidence=None, memory_loaded=False,
                judge_network_accessed=False, judge_provider_id="openai",
                council_adapter=None):
    judge_events = []
    judge = ComposedHeavyJudge(
        backend=ModelBackend(
            action, memory_loaded=memory_loaded,
            network_accessed=judge_network_accessed,
        ),
        behavioral_judge=HeavyJudge(),
        evidence_sink=judge_events.append,
    )
    router = AIRouter(providers=providers)
    raw_sink = evidence if evidence is not None else (lambda event: None)

    def acknowledged_sink(event):
        result = raw_sink(event)
        if isinstance(result, EvidenceAppendReceipt):
            return result
        return EvidenceAppendReceipt(
            event_type=event["event"],
            task_id=event["task_id"],
            event_id=f"test-event-{len(judge_events) + 1}",
            event_hash=event["event_hash"],
            sequence=len(judge_events),
        )

    router.configure_governance(
        judge=judge,
        authorization_verification_key=KEY,
        owner_id=OWNER,
        required_scope=SCOPE,
        evidence_sink=acknowledged_sink,
        council_adapter=council_adapter or (
            lambda payload: {
                "action": "PASS",
                "candidate": payload["candidate"],
                "source_provider_id": payload["source_provider_id"],
                "votes": {"grok": "PASS", "gpt_codex": "PASS", "claude": "PASS"},
            }
        ),
        judge_provider_id=judge_provider_id,
    )
    return router, judge_events


def run_chat(router, **kwargs):
    return asyncio.run(router.chat(
        "Explain the sky.",
        authorization_proof=proof(),
        task_id=TASK,
        **kwargs,
    ))


def test_missing_proof_denies_before_provider_call():
    provider = Provider()
    router, _ = make_router({"xai": provider})
    with pytest.raises(PermissionError, match="proof"):
        asyncio.run(router.chat("Explain the sky.", task_id=TASK))
    assert provider.calls == 0


def test_invalid_proof_denies_before_provider_call():
    provider = Provider()
    router, _ = make_router({"xai": provider})
    with pytest.raises(PermissionError):
        asyncio.run(router.chat(
            "Explain the sky.", authorization_proof="invalid.proof", task_id=TASK
        ))
    assert provider.calls == 0


def test_composed_pass_and_dual_gate_release_record_receipt():
    provider = Provider()
    events = []
    router, judge_events = make_router({"xai": provider}, evidence=events.append,
                                       memory_loaded=True, judge_network_accessed=False)
    result = run_chat(router)
    expected = "sha3-512:" + hashlib.sha3_512(result["text"].encode()).hexdigest()
    assert result["text"] == "Rayleigh scattering explains the blue sky."
    assert result["release_receipt"]["output_hash"] == expected
    assert result["release_receipt"]["release_status"] == "PASS"
    assert provider.calls == 1
    assert judge_events[-1]["memory_loaded"] is True
    assert events[-1]["event"] == "OUTENV_RELEASE_AUTHORIZED"
    assert events[-1]["authorization"] == "gate-proof-async-test"


def test_non_pass_is_escrowed_and_never_falls_back():
    first, second = Provider(), Provider()
    events = []
    router, _ = make_router({"xai": first, "anthropic": second},
                            action="REWRITE", evidence=events.append)
    with pytest.raises(OutputWithheldError, match="REWRITE"):
        run_chat(router)
    assert first.calls == 1
    assert second.calls == 0
    assert events[-1]["event"] == "ESCROW_PENDING_REVIEW"


def test_evidence_failure_before_provider_blocks_execution():
    provider = Provider()

    def broken(_event):
        raise OSError("evidence unavailable")

    router, _ = make_router({"xai": provider}, evidence=broken)
    with pytest.raises(RuntimeError, match="SCAR evidence"):
        run_chat(router)
    assert provider.calls == 0


def test_release_evidence_failure_withholds_candidate():
    provider = Provider()
    seen = []

    def fail_release(event):
        seen.append(event)
        if event.get("what") == "OUTENV_RELEASE_AUTHORIZED":
            raise OSError("release evidence unavailable")

    router, _ = make_router({"xai": provider}, evidence=fail_release)
    with pytest.raises(RuntimeError, match="release evidence"):
        run_chat(router)
    assert provider.calls == 1
    assert any(item.get("what") == "OUTENV_RELEASE_AUTHORIZED" for item in seen)




def test_async_router_requires_council_before_judge():
    calls = []
    provider = Provider()
    router, _ = make_router(
        {"xai": provider},
        council_adapter=lambda payload: (
            calls.append(payload) or {
                "action": "PASS",
                "candidate": "Council-approved candidate.",
                "source_provider_id": "xai",
                "votes": {"grok": "PASS", "gpt_codex": "PASS", "claude": "PASS"},
            }
        ),
    )
    result = run_chat(router)
    assert calls and calls[0]["candidate"] == provider.result["text"]
    assert result["text"] == "Council-approved candidate."


def test_async_router_rejects_judge_from_source_provider():
    provider = Provider()
    router, _ = make_router({"xai": provider}, judge_provider_id="xai")
    with pytest.raises(RuntimeError, match="cannot judge its own"):
        run_chat(router)
    assert provider.calls == 1


def test_provider_fallback_only_after_transport_failure():
    first = Provider(error=httpx.ConnectTimeout("network timeout"))
    second = Provider()
    events = []
    router, _ = make_router({"xai": first, "anthropic": second}, evidence=events.append)
    result = run_chat(router)
    assert result["text"] == second.result["text"]
    assert first.calls == 1
    assert second.calls == 1
    assert result["fallback_from"] == [{"provider": "xai", "error": "ConnectTimeout"}]


def test_provider_auth_failure_is_terminal_not_fallback():
    request = httpx.Request("POST", "https://provider.invalid/chat")
    response = httpx.Response(401, request=request)
    first = Provider(error=httpx.HTTPStatusError("unauthorized", request=request, response=response))
    second = Provider()
    router, _ = make_router({"xai": first, "anthropic": second})
    with pytest.raises(RuntimeError, match="non-retryably"):
        run_chat(router)
    assert first.calls == 1
    assert second.calls == 0


def test_malformed_provider_response_is_terminal_not_fallback():
    first = Provider(result={"unexpected": "shape"})
    second = Provider()
    router, _ = make_router({"xai": first, "anthropic": second})
    with pytest.raises(RuntimeError, match="malformed"):
        run_chat(router)
    assert first.calls == 1
    assert second.calls == 0


def test_health_check_does_not_probe_provider_network():
    provider = Provider()
    provider.health_check = lambda: (_ for _ in ()).throw(AssertionError("must not probe"))
    router, _ = make_router({"xai": provider})
    result = asyncio.run(router.health_check())
    assert result["providers"]["xai"]["probe_performed"] is False
    assert provider.calls == 0


def test_scar_adapter_accepts_normalized_dual_gate_event_and_preserves_5w1h():
    ledger = SCARLedger("device:async-router-test", Root())
    sink = SCARLedgerSink(ledger)
    provider = Provider()
    router, _ = make_router({"xai": provider}, evidence=sink)
    run_chat(router)
    assert ledger.verify_chain()
    release = ledger.events[-1]
    assert release.event_type == "OUTENV_RELEASE_AUTHORIZED"
    assert release.metadata["evidence"]["authorization"] == "gate-proof-async-test"
    assert release.metadata["evidence"]["result"] == "PASS"
