from __future__ import annotations

import hashlib
import pytest

from backend.coordination.authorization_proof import issue_gate_authorization_proof
from backend.coordination.dual_gate_path import (
    DualGateDenied, ReleaseIntegrityError, authorize_before_route, verify_before_release,
)

KEY=b"dual-gate-test-key"
def proof(task="task-1",owner="owner",scope=("repo/",)):
    return issue_gate_authorization_proof(proof_id="proof-1",owner_id=owner,task_id=task,scope=scope,
        decision="OWNER_AUTHORIZED",policy_hash="sha256:policy",issued_at=100,expires_at=500,secret=KEY)
def claims():
    return authorize_before_route(proof(),verification_key=KEY,task_id="task-1",owner_id="owner",
                                  required_scope=("repo/",),now=200)
def candidate_result(output="approved"):
    digest="sha3-512:"+hashlib.sha3_512(output.encode()).hexdigest()
    return {"status":"PASS","output":output,"output_hash":digest,
            "judge_verdict":{"action":"PASS","task_id":"task-1","candidate_hash":digest,
                             "output_hash":digest,"policy_hash":"sha256:policy","judge_id":"independent"}}
def ack(event):
    return {"status":"APPENDED","verified":True,"event_hash":event["event_hash"],
            "task_id":event["task_id"],"output_hash":event["output_hash"],
            "ledger_event_hash":"ledger-sha256:test","signature":"fixture-signature"}

def test_gate_one_binds_owner_task_and_scope():
    assert claims().proof_id == "proof-1"
def test_gate_one_rejects_wrong_owner():
    with pytest.raises(DualGateDenied,match="owner identity"):
        authorize_before_route(proof(),verification_key=KEY,task_id="task-1",owner_id="other",
                               required_scope=("repo/",),now=200)
def test_gate_two_rejects_non_pass():
    with pytest.raises(DualGateDenied,match="only Heavy Judge PASS"):
        verify_before_release(claims(),{"status":"ESCROW_PENDING_REVIEW"},expected_task_id="task-1",evidence_sink=ack)
def test_gate_two_rejects_digest_mismatch():
    result=candidate_result(); result["output_hash"]="sha3-512:bad"
    with pytest.raises(ReleaseIntegrityError,match="digest mismatch"):
        verify_before_release(claims(),result,expected_task_id="task-1",evidence_sink=ack)
def test_gate_two_requires_full_verdict_binding():
    result=candidate_result(); result["judge_verdict"]={"action":"PASS"}
    with pytest.raises(ReleaseIntegrityError,match="required bindings"):
        verify_before_release(claims(),result,expected_task_id="task-1",evidence_sink=ack)
def test_gate_two_rejects_task_policy_and_candidate_mismatch():
    for key,value,match in (("task_id","other","task_id mismatch"),("policy_hash","sha256:other","policy hash mismatch"),("candidate_hash","sha3-512:bad","hash does not match")):
        result=candidate_result(); result["judge_verdict"][key]=value
        with pytest.raises(ReleaseIntegrityError,match=match):
            verify_before_release(claims(),result,expected_task_id="task-1",evidence_sink=ack)
def test_gate_two_requires_verifiable_receipt():
    def no_signature(event):
        return {"status":"APPENDED","verified":True,"event_hash":event["event_hash"],
                "task_id":event["task_id"],"output_hash":event["output_hash"]}
    with pytest.raises(ReleaseIntegrityError,match="signed SCAR"):
        verify_before_release(claims(),candidate_result(),expected_task_id="task-1",evidence_sink=no_signature)
def test_gate_two_rejects_receipt_for_different_event():
    def wrong(event):
        result=ack(event); result["event_hash"]="sha3-512:wrong"; return result
    with pytest.raises(ReleaseIntegrityError,match="event_hash mismatch"):
        verify_before_release(claims(),candidate_result(),expected_task_id="task-1",evidence_sink=wrong)
def test_gate_two_append_exception_fails_closed():
    def fail(_event): raise OSError("ledger unavailable")
    with pytest.raises(ReleaseIntegrityError,match="append failed"):
        verify_before_release(claims(),candidate_result(),expected_task_id="task-1",evidence_sink=fail)
