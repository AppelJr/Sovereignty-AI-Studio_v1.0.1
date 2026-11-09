from __future__ import annotations

import hashlib
import pytest

from backend.coordination.authorization_proof import issue_gate_authorization_proof
from backend.coordination.dual_gate_path import EvidenceAppendReceipt
from sovereign_core.heavy_judge import HeavyJudge
from sovereign_core.judge_composition import ComposedHeavyJudge
from sovereign_core.smart_provider_router import EscrowPending, SmartProviderRouter

KEY = b"router-composition-test-key"

class Backend:
    model_id = "fixture-judge"
    provider_id = "sovereign-local-judge"

    def __init__(self, action: str = "PASS"):
        self.action = action
    def evaluate(self, candidate, context):
        return {"action":self.action,"reason":"test fixture","model_id":self.model_id,
                "memory_loaded":False,"network_accessed":False}

class State:
    max_tokens = 4096
    token_count = 0

class TokenManager:
    config = {"providers":{"xai":{"base_max_tokens":4096}}}
    def __init__(self):
        self.states = {"xai":State()}
    def start_session(self, provider):
        self.states[provider] = State()
    def consume_tokens(self, provider, tokens):
        return {"output":"Rayleigh scattering explains the blue sky.","provider":provider}

def gate_proof(decision="OWNER_AUTHORIZED"):
    return issue_gate_authorization_proof(proof_id="router-proof",owner_id="owner",task_id="task-1",
        scope=("repo/",),decision=decision,policy_hash="sha256:test-policy",issued_at=100,
        expires_at=500,secret=KEY)

def council(action="PASS", payload=None):
    votes = {"grok": "PASS", "gpt_codex": "PASS", "claude": "PASS"}
    if action != "PASS":
        votes["grok"] = action
    payload = payload or {}
    candidate = payload.get("candidate", "Rayleigh scattering explains the blue sky.")
    return {
        "action": action,
        "votes": votes,
        "candidate": candidate,
        "source_provider_id": "council:aggregate",
        "proposals": {
            "grok": {"provider_id": "xai", "candidate": candidate, "vote": votes["grok"]},
            "gpt_codex": {"provider_id": "openai", "candidate": candidate, "vote": votes["gpt_codex"]},
            "claude": {"provider_id": "anthropic", "candidate": candidate, "vote": votes["claude"]},
        },
    }


def make_router(model_action="PASS", council_action="PASS", events=None,
                judge_provider_id="sovereign-local-judge"):
    audit = events if events is not None else []
    behavioral = HeavyJudge(evidence_sink=audit.append)
    backend = Backend(model_action)
    backend.provider_id = judge_provider_id
    judge = ComposedHeavyJudge(
        backend=backend,
        behavioral_judge=behavioral,
        evidence_sink=audit.append,
    )
    router = SmartProviderRouter(
        TokenManager(),
        council_adapter=lambda payload: council(council_action, payload),
        judge=judge,
        judge_provider_id=judge_provider_id,
    )
    return router, audit

def successful_ack(event):
    return {"status":"APPENDED","verified":True,"event_hash":event["event_hash"],
            "task_id":event["task_id"],"output_hash":event["output_hash"],
            "ledger_event_hash":"ledger-sha256:test","signature":"test-signature"}

def invoke(router, *, proof=None, evidence=None):
    raw_sink = evidence or (lambda _event: None)

    def acknowledged_sink(event):
        result = raw_sink(event)
        if isinstance(result, EvidenceAppendReceipt):
            return result
        return EvidenceAppendReceipt(
            event_type=event["what"],
            task_id=event["task_id"],
            event_id="test-release-event",
            event_hash="a" * 64,
            signature="test-signature",
            sequence=0,
        )

    return router.consume_with_routing(
        12,
        "Explain the sky.",
        context="general",
        authorization_proof=proof or gate_proof(),
        verification_key=KEY,
        task_id="task-1",
        owner_id="owner",
        required_scope=("repo/",),
        evidence_sink=acknowledged_sink,
        now=200,
    )


def test_router_releases_only_after_composed_judge_and_both_gates():
    router, events = make_router()
    result = invoke(router, evidence=events.append)
    assert result["status"] == "PASS"
    assert result["used_judge"] is True
    assert result["evidence_receipt"]["event_type"] == "OUTENV_RELEASE_AUTHORIZED"
    assert result["evidence_receipt"]["task_id"] == "task-1"
    assert result["evidence_receipt"]["signature"]
    assert result["output_hash"] == (
        "sha3-512:" + hashlib.sha3_512(result["output"].encode("utf-8")).hexdigest()
    )
    assert any(event.get("what") == "COMPOSED_JUDGE_VERDICT" for event in events)
    assert events[-1]["what"] == "OUTENV_RELEASE_AUTHORIZED"

def test_non_pass_judge_never_releases():
    router, _events=make_router(model_action="REWRITE")
    result=invoke(router)
    assert result["status"] == "ESCROW_PENDING_REVIEW"
    assert "output" not in result

@pytest.mark.parametrize("action",["REWRITE","YANK"])
def test_council_non_pass_never_releases(action):
    router, _events=make_router(council_action=action)
    result=invoke(router)
    assert result["status"] == "ESCROW_PENDING_REVIEW"
    assert "output" not in result

def test_invalid_gate_proof_blocks_provider_execution():
    router,_=make_router()
    with pytest.raises(PermissionError): invoke(router,proof="invalid.proof")

def test_missing_council_lane_blocks_release():
    router, _events = make_router()
    router.council_adapter = lambda _payload: {
        "action": "PASS",
        "votes": {"grok": "PASS"},
    }
    with pytest.raises(RuntimeError, match="three lanes"):
        invoke(router)


def test_router_rejects_legacy_non_composed_judge():
    with pytest.raises(TypeError, match="ComposedHeavyJudge"):
        SmartProviderRouter(
            TokenManager(),
            council_adapter=lambda _payload: council(),
            judge=HeavyJudge(),
            judge_provider_id="sovereign-local-judge",
        )




def test_judge_unavailable_is_explicit_hold_not_provider_fallback():
    router, _events = make_router()
    def unavailable(_candidate, _context):
        raise RuntimeError("judge backend offline")
    router.judge.backend.evaluate = unavailable
    result = invoke(router)
    assert result["status"] == "ESCROW_PENDING_REVIEW"
    assert result["action"] == "UNAVAILABLE"
    assert result["judge_verdict"]["action"] == "UNAVAILABLE"


def test_router_rejects_provider_as_its_own_judge():
    router, _events = make_router(judge_provider_id="xai")
    with pytest.raises(RuntimeError, match="cannot judge its own"):
        invoke(router)


def test_release_evidence_failure_blocks_output():
    router, _events = make_router()

    def broken(_event):
        raise OSError("evidence store unavailable")

    with pytest.raises(RuntimeError, match="release evidence"):
        invoke(router, evidence=broken)
