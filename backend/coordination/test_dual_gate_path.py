from __future__ import annotations

import hashlib
import pytest

from backend.coordination.authorization_proof import issue_gate_authorization_proof
from backend.coordination.dual_gate_path import (
    DualGateDenied, EvidenceAppendReceipt, ReleaseIntegrityError,
    authorize_before_route, verify_before_release,
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


def release(result, sink):
    return verify_before_release(
        proof(), result, verification_key=KEY, expected_task_id="task-1",
        expected_owner_id="owner", required_scope=("repo/",),
        evidence_sink=sink, now=200,
    )


def test_gate_one_binds_owner_task_and_scope():
    assert claims().proof_id == "proof-1"


def test_gate_one_rejects_wrong_owner():
    with pytest.raises(DualGateDenied, match="owner identity"):
        authorize_before_route(
            proof(), verification_key=KEY, task_id="task-1",
            owner_id="other", required_scope=("repo/",), now=200,
        )


def test_gate_two_reverifies_expiry_before_release():
    expired = proof()
    with pytest.raises(DualGateDenied, match="authorization failed"):
        verify_before_release(
            expired, valid_result(), verification_key=KEY,
            expected_task_id="task-1", expected_owner_id="owner",
            required_scope=("repo/",), evidence_sink=acknowledged, now=500,
        )


def test_gate_two_rejects_non_pass():
    with pytest.raises(DualGateDenied, match="only Heavy Judge PASS"):
        release({"status": "ESCROW_PENDING_REVIEW"}, lambda _event: None)


def test_gate_two_rejects_digest_mismatch():
    with pytest.raises(ReleaseIntegrityError, match="digest mismatch"):
        release({"status": "PASS", "output": "x", "output_hash": "sha3-512:bad"},
                lambda _event: None)


def valid_result(output="approved"):
    digest = "sha3-512:" + hashlib.sha3_512(output.encode()).hexdigest()
    return {
        "status": "PASS",
        "output": output,
        "output_hash": digest,
        "source_provider_id": "xai",
        "judge_verdict": {
            "action": "PASS",
            "task_id": "task-1",
            "policy_hash": "sha256:policy",
            "candidate_hash": digest,
            "output_hash": digest,
            "judge_id": "heavy-judge-v1",
            "judge_provider_id": "sovereign-local-judge",
            "contributing_provider_ids": ["xai", "openai", "anthropic"],
        },
    }


def acknowledged(event):
    return EvidenceAppendReceipt(
        event_type=event["what"],
        task_id=event["task_id"],
        event_id="test-event-1",
        event_hash="a" * 64,
        signature="test-signature",
        sequence=0,
    )


def test_gate_two_requires_evidence_before_release():
    def fail(_event):
        raise OSError("ledger unavailable")
    with pytest.raises(ReleaseIntegrityError, match="evidence append failed"):
        release(valid_result(), fail)


def test_gate_two_rejects_verdict_policy_mismatch():
    result = valid_result()
    result["judge_verdict"]["policy_hash"] = "sha256:wrong-policy"
    with pytest.raises(ReleaseIntegrityError, match="policy_hash mismatch"):
        release(result, acknowledged)


def test_gate_two_rejects_verdict_task_mismatch():
    result = valid_result()
    result["judge_verdict"]["task_id"] = "other-task"
    with pytest.raises(ReleaseIntegrityError, match="task_id mismatch"):
        release(result, acknowledged)


def test_gate_two_rejects_stale_candidate_verdict():
    result = valid_result("changed after review")
    result["judge_verdict"]["candidate_hash"] = "sha3-512:stale"
    with pytest.raises(ReleaseIntegrityError, match="candidate hash"):
        release(result, acknowledged)


def test_gate_two_rejects_provider_self_judging():
    result = valid_result()
    result["judge_verdict"]["judge_provider_id"] = "xai"
    with pytest.raises(ReleaseIntegrityError, match="cannot judge its own"):
        release(result, acknowledged)


def test_gate_two_rejects_unacknowledged_evidence():
    with pytest.raises(ReleaseIntegrityError, match="no signed append acknowledgment"):
        release(valid_result(), lambda _event: None)


def test_gate_two_releases_only_after_bound_evidence_receipt():
    receipt = release(valid_result(), acknowledged)
    assert receipt.release_status == "PASS"
    assert receipt.evidence_receipt.event_type == "OUTENV_RELEASE_AUTHORIZED"
    assert receipt.evidence_receipt.task_id == "task-1"
