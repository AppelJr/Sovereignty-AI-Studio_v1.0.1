"""Tests for Shortcut Flow to Gate/Genesis routing."""
from __future__ import annotations

import pytest

from backend.coordination.authorization_proof import issue_gate_authorization_proof
from backend.coordination.genesis_adapter import GenesisRouterAdapter
from backend.coordination.shortcut_router import ShortcutRouter, classify_prompt

SECRET = b"test-only-gate-authorization-proof"


def document(prompt: str = "Fix the repository code") -> dict:
    return {
        "request": {
            "request_id": "req-1",
            "prompt": prompt,
            "permissions": {
                "device_access": False,
                "memory_access": False,
                "external_models": True,
            },
            "routing_decision": {"judge_required": True},
        }
    }


def allow(task, _request):
    """Gate ALLOW path must emit a signed gate_proof."""
    proof = issue_gate_authorization_proof(
        proof_id="proof-shortcut",
        owner_id=task.owner,
        task_id=task.task_id,
        scope=task.scope,
        decision="OWNER_AUTHORIZED",
        policy_hash="sha256:policy",
        evidence_sequence=1,
        issued_at=1_000_000_000,
        expires_at=1_000_000_300,
        secret=SECRET,
    )
    return {
        "decision": "OWNER_AUTHORIZED",
        "policy_hash": "sha256:policy",
        "gate_proof": proof,
    }


def router() -> ShortcutRouter:
    return ShortcutRouter(
        allow,
        genesis=GenesisRouterAdapter(proof_secret=SECRET, now=1_000_000_100),
    )


def test_classification_precedence_prefers_coding() -> None:
    assert classify_prompt("Analyze this repository and summarize the code") == "CODING"


def test_shortcut_router_creates_task_and_route_without_execution() -> None:
    result = router().route(document())
    assert result.task.task_id == "req-1"
    assert result.task.mode == "online"
    assert result.task_type == "CODING"
    assert result.route is not None
    assert result.route.route == "sovereignty-runtime"
    assert "gate_proof" in result.authorization


def test_memory_permission_is_not_granted_by_router() -> None:
    result = router().route(document())
    assert "memory" not in result.task.scope


def test_denied_gate_returns_escalation_and_no_route() -> None:
    def deny(_task, _request):
        return {
            "decision": "DENY",
            "reason_code": "POLICY_DENIED",
            "policy_hash": "sha256:p",
        }

    result = ShortcutRouter(
        deny,
        genesis=GenesisRouterAdapter(proof_secret=SECRET, now=1_000_000_100),
    ).route(document())
    assert result.route is None
    assert result.escalation is not None
    assert result.escalation.reason_code == "POLICY_DENIED"


def test_allow_without_gate_proof_escalates_fail_closed() -> None:
    def bare_allow(_task, _request):
        return {"decision": "OWNER_AUTHORIZED", "policy_hash": "sha256:policy"}

    result = ShortcutRouter(
        bare_allow,
        genesis=GenesisRouterAdapter(proof_secret=SECRET, now=1_000_000_100),
    ).route(document())
    assert result.route is None
    assert result.escalation is not None
    assert result.escalation.reason_code == "GATE_PROOF_REQUIRED"


def test_missing_request_id_fails_closed() -> None:
    payload = document()
    payload["request"].pop("request_id")
    with pytest.raises(ValueError, match="request_id"):
        router().route(payload)
