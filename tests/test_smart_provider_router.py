from __future__ import annotations

import hashlib

import pytest

from backend.coordination.authorization_proof import issue_gate_authorization_proof
from sovereign_core.heavy_judge import HeavyJudge
from sovereign_core.smart_provider_router import SmartProviderRouter, EscrowPending


KEY = b"router-test-key"


class State:
    max_tokens = 4096
    token_count = 0


class TokenManager:
    config = {"providers": {"xai": {"base_max_tokens": 4096}}}
    states = {"xai": State()}

    def start_session(self, provider):
        self.states[provider] = State()

    def consume_tokens(self, provider, tokens):
        return {"output": "Rayleigh scattering explains the blue sky.", "provider": provider}


def gate_proof(decision="OWNER_AUTHORIZED"):
    return issue_gate_authorization_proof(
        proof_id="router-proof",
        owner_id="owner",
        task_id="task-1",
        scope=("repo/",),
        decision=decision,
        policy_hash="sha256:policy",
        issued_at=100,
        expires_at=500,
        secret=KEY,
    )


def council(action="PASS"):
    votes = {"grok": "PASS", "gpt_codex": "PASS", "claude": "PASS"}
    if action == "YANK":
        votes["grok"] = "YANK"
    return {"action": action, "votes": votes}


def make_router(action="PASS"):
    return SmartProviderRouter(
        TokenManager(),
        council_adapter=lambda _payload: council(action),
        judge=HeavyJudge(),
    )


def test_router_requires_gate_proof_and_releases_only_after_both_gates():
    events = []
    result = make_router().consume_with_routing(
        12, "Explain the sky.", context="general",
        authorization_proof=gate_proof(), verification_key=KEY,
        task_id="task-1", owner_id="owner", required_scope=("repo/",),
        evidence_sink=events.append, now=200,
    )
    assert result["status"] == "PASS"
    assert result["output_hash"] == (
        "sha3-512:" + hashlib.sha3_512(result["output"].encode()).hexdigest()
    )
    assert events[-1]["what"] == "OUTENV_RELEASE_AUTHORIZED"


def test_router_yank_is_escrowed_and_never_released():
    events = []
    result = make_router("YANK").consume_with_routing(
        12, "Explain the sky.", context="general",
        authorization_proof=gate_proof(), verification_key=KEY,
        task_id="task-1", owner_id="owner", required_scope=("repo/",),
        evidence_sink=events.append, now=200,
    )
    assert result["status"] == "ESCROW_PENDING_REVIEW"
    assert "output" not in result
    assert events[-1]["what"] == "ESCROW_PENDING_REVIEW"


def test_router_rejects_invalid_gate_proof():
    with pytest.raises(PermissionError):
        make_router().consume_with_routing(
            12, "Explain the sky.", context="general",
            authorization_proof="forged.payload", verification_key=KEY,
            task_id="task-1", owner_id="owner", required_scope=("repo/",),
            evidence_sink=lambda _event: None, now=200,
        )


def test_router_rejects_missing_council_lane():
    router = SmartProviderRouter(
        TokenManager(),
        council_adapter=lambda _payload: {"action": "PASS", "votes": {"grok": "PASS"}},
        judge=HeavyJudge(),
    )
    with pytest.raises(RuntimeError, match="three lanes"):
        router.consume_with_routing(
            12, "Explain the sky.", context="general",
            authorization_proof=gate_proof(), verification_key=KEY,
            task_id="task-1", owner_id="owner", required_scope=("repo/",),
            evidence_sink=lambda _event: None, now=200,
        )
