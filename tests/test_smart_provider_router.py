from __future__ import annotations

import hashlib
import pytest

from backend.coordination.authorization_proof import issue_gate_authorization_proof
from backend.coordination.dual_gate_path import (
    DualGateDenied,
    ReleaseIntegrityError,
    authorize_before_route,
    verify_before_release,
)

KEY = b"test-only-key"


def proof(task="task-1", owner="owner", scope=("repo/",)):
    return issue_gate_authorization_proof(
        proof_id="proof-1", owner_id=owner, task_id=task, scope=scope,
        decision="OWNER_AUTHORIZED", policy_hash="sha256:policy",
        issued_at=100, expires_at=500, secret=KEY,
    )


def claims():
    return authorize_before_route(
        proof(), verification_key=KEY, task_id="task-1",
        owner_id="owner", required_scope=("repo/",), now=200,
    )


def test_gate_one_binds_owner_task_and_scope():
    assert claims().proof_id == "proof-1"


def test_gate_one_rejects_wrong_owner():
    with pytest.raises(DualGateDenied, match="owner identity"):
        authorize_before_route(
            proof(), verification_key=KEY, task_id="task-1",
            owner_id="other", required_scope=("repo/",), now=200,
        )


def test_gate_two_rejects_non_pass():
    with pytest.raises(DualGateDenied, match="only Heavy Judge PASS"):
        verify_before_release(
            claims(), {"status": "ESCROW_PENDING_REVIEW"},
            expected_task_id="task-1", evidence_sink=lambda _event: None,
        )


def test_gate_two_rejects_digest_mismatch():
    with pytest.raises(ReleaseIntegrityError, match="digest mismatch"):
        verify_before_release(
            claims(), {"status": "PASS", "output": "x", "output_hash": "sha3-512:bad"},
            expected_task_id="task-1", evidence_sink=lambda _event: None,
        )


def test_gate_two_requires_verifiable_receipt():
    output = "approved"
    result = {"status": "PASS", "output": output,
              "output_hash": "sha3-512:" + hashlib.sha3_512(output.encode()).hexdigest()}

    def fail(_event):
        return {"status": "OK"}

    with pytest.raises(ReleaseIntegrityError, match="verifiable receipt"):
        verify_before_release(
            claims(), result, expected_task_id="task-1", evidence_sink=fail,
        )


def test_gate_two_requires_evidence_before_release():
    output = "approved"
    result = {"status": "PASS", "output": output,
              "output_hash": "sha3-512:" + hashlib.sha3_512(output.encode()).hexdigest()}

    def fail(_event):
        raise OSError("ledger unavailable")

    with pytest.raises(ReleaseIntegrityError, match="evidence append failed"):
        verify_before_release(
            claims(), result, expected_task_id="task-1", evidence_sink=fail,
        )


def test_gate_two_requires_matching_judge_verdict_hash():
    output = "approved"
    result = {
        "status": "PASS",
        "output": output,
        "output_hash": "sha3-512:" + hashlib.sha3_512(output.encode()).hexdigest(),
        "judge_verdict": {"action": "PASS", "output_hash": "sha3-512:bad"},
    }
    with pytest.raises(ReleaseIntegrityError, match="judge verdict hash"):
        verify_before_release(
            claims(), result, expected_task_id="task-1", evidence_sink=lambda event: {"status": "OK", "event_hash": event["event_hash"]},
        )


"""
This file intentionally documents the fail-closed release contract.
"""



