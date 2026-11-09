from __future__ import annotations

import hashlib

import pytest

from backend.coordination.authorization_proof import issue_gate_authorization_proof
from backend.coordination.dual_gate_path import EvidenceAppendReceipt
from sovereign_core.heavy_judge import HeavyJudge
from sovereign_core.judge_composition import ComposedHeavyJudge
from sovereign_core.smart_provider_router import SmartProviderRouter, EscrowPending


KEY = b"router-composition-test-key"


class Backend:
    model_id = "fixture-judge"

    def __init__(self, action: str = "PASS"):
        self.action = action

    def evaluate(self, candidate: str, context: str):
        return {"action": self.action, "reason": "test fixture", "model_id": self.model_id, "memory_loaded": False, "network_accessed": False}


class State:
    max_tokens = 4096
    token_count = 0


class TokenManager:
    config = {"providers": {"xai": {"base_max_tokens": 4096}}}

    def __init__(self):
        self.states = {"xai": State()}

    def start_session(self, provider):
        self.states[provider] = State()

    def consume_tokens(self, provider, tokens):
        return {"output": "Rayleigh scattering explains the blue sky.", "provider": provider}


def gate_proof(decision="OWNER_AUTHORIZED"):
    return issue_gate_authorization_proof(
        proof_id="router-composed-proof",
        owner_id="owner",
        task_id="task-1",
        scope=("repo/",),
        decision=decision,
        policy_hash="sha256:test-policy",
        issued_at=100,
        expires_at=500,
        secret=KEY,
    )


def council(action="PASS", payload=None):
    votes = {"grok": "PASS", "gpt_codex": "PASS", "claude": "PASS"}
    if action != "PASS":
        votes["grok"] = action
    payload = payload or {}
    return {
        "action": action,
        "votes": votes,
        "candidate": payload.get("candidate", "Rayleigh scattering explains the blue sky."),
        "source_provider_id": payload.get("source_provider_id", "xai"),
    }


def make_router(model_action="PASS", council_action="PASS", events=None,
                judge_provider_id="anthropic"):
    audit = events if events is not None else []
    behavioral = HeavyJudge(evidence_sink=audit.append)
    judge = ComposedHeavyJudge(
        backend=Backend(model_action),
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
            event_hash="sha256:test-release-event",
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
    assert result["output_hash"] == (
        "sha3-512:" + hashlib.sha3_512(result["output"].encode("utf-8")).hexdigest()
    )
    assert any(event.get("what") == "COMPOSED_JUDGE_VERDICT" for event in events)
    assert events[-1]["what"] == "OUTENV_RELEASE_AUTHORIZED"


@pytest.mark.parametrize("model_action", ["REWRITE", "COUNCIL", "YANK"])
def test_composed_judge_escalation_never_releases_output(model_action):
    router, events = make_router(model_action=model_action)
    result = invoke(router, evidence=events.append)
    assert result["status"] == "ESCROW_PENDING_REVIEW"
    assert "output" not in result
    assert events[-1]["what"] == "ESCROW_PENDING_REVIEW"


def test_behavioral_yank_overrides_model_pass():
    router, events = make_router()
    # The provider fixture returns safe text; directly verify the composed
    # judge's restrictive behavioral result independently of routing.
    judge = router.judge
    result = judge.review("The password=secret value is exposed.")
    assert result["verdict"]["action"] == "YANK"
    assert result["final_output"] is None
    assert events[-1]["what"] == "COMPOSED_JUDGE_VERDICT"


def test_invalid_gate_proof_blocks_provider_execution():
    router, _events = make_router()
    with pytest.raises(PermissionError):
        invoke(router, proof="invalid.proof")


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
        )




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
