"""Adversarial tests for Gate authorization proofs."""
from __future__ import annotations

import pytest

from backend.coordination.authorization_proof import (
    AuthorizationProofError,
    issue_gate_authorization_proof,
    verify_gate_authorization_proof,
)

SECRET = b"test-only-gate-authorization-proof"


def _issue(**overrides):
    kwargs = {
        "proof_id": "proof-001",
        "owner_id": "owner",
        "task_id": "task-1",
        "scope": ("repo/",),
        "decision": "OWNER_AUTHORIZED",
        "policy_hash": "sha256:policy",
        "policy_version": "1",
        "reason_code": "AUTHORIZED",
        "evidence_sequence": 7,
        "issued_at": 1_000_000_000,
        "expires_at": 1_000_000_300,
        "secret": SECRET,
    }
    kwargs.update(overrides)
    return issue_gate_authorization_proof(**kwargs)


def test_valid_proof_verifies():
    token = _issue()
    claims = verify_gate_authorization_proof(
        token, secret=SECRET, now=1_000_000_100, expected_task_id="task-1"
    )
    assert claims.owner_id == "owner"
    assert claims.task_id == "task-1"
    assert claims.decision == "OWNER_AUTHORIZED"
    assert claims.policy_hash == "sha256:policy"
    assert claims.evidence_sequence == 7
    assert claims.allows_decision("OWNER_AUTHORIZED", "ALLOW")


def test_forgeable_dict_is_rejected():
    with pytest.raises(AuthorizationProofError, match="forgeable"):
        verify_gate_authorization_proof(
            {"decision": "OWNER_AUTHORIZED", "policy_hash": "sha256:policy"},
            secret=SECRET,
            now=1_000_000_100,
        )


def test_tampered_payload_is_rejected():
    token = _issue()
    payload, signature = token.split(".", 1)
    tampered = payload[:-1] + ("A" if payload[-1] != "A" else "B")
    with pytest.raises(AuthorizationProofError, match="signature"):
        verify_gate_authorization_proof(
            f"{tampered}.{signature}", secret=SECRET, now=1_000_000_100
        )


def test_expired_proof_is_rejected():
    token = _issue(expires_at=1_000_000_050)
    with pytest.raises(AuthorizationProofError, match="expired"):
        verify_gate_authorization_proof(token, secret=SECRET, now=1_000_000_100)


def test_task_id_mismatch_is_rejected():
    token = _issue(task_id="task-1")
    with pytest.raises(AuthorizationProofError, match="task_id mismatch"):
        verify_gate_authorization_proof(
            token, secret=SECRET, now=1_000_000_100, expected_task_id="task-OTHER"
        )


def test_scope_escalation_is_rejected():
    token = _issue(scope=("repo/",))
    with pytest.raises(AuthorizationProofError, match="missing required scope"):
        verify_gate_authorization_proof(
            token,
            secret=SECRET,
            now=1_000_000_100,
            expected_task_id="task-1",
            required_scope=("repo/", "admin"),
        )


def test_deny_decision_is_rejected():
    token = _issue(decision="DENY")
    with pytest.raises(AuthorizationProofError, match="deny"):
        verify_gate_authorization_proof(
            token, secret=SECRET, now=1_000_000_100, expected_task_id="task-1"
        )


def test_embedded_gate_proof_mapping_verifies():
    token = _issue()
    claims = verify_gate_authorization_proof(
        {"gate_proof": token, "decision": "IGNORED"},
        secret=SECRET,
        now=1_000_000_100,
        expected_task_id="task-1",
    )
    assert claims.decision == "OWNER_AUTHORIZED"
