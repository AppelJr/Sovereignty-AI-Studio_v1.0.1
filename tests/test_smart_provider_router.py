from __future__ import annotations

import hashlib
import pytest

from backend.coordination.authorization_proof import issue_gate_authorization_proof
from backend.coordination.dual_gate_path import ReleaseIntegrityError
from sovereign_core.heavy_judge import HeavyJudge
from sovereign_core.judge_composition import ComposedHeavyJudge
from sovereign_core.smart_provider_router import EscrowPending, SmartProviderRouter

KEY = b"router-composition-test-key"

class Backend:
    model_id = "independent-judge"
    def __init__(self, action="PASS"):
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

def council(action="PASS"):
    votes={"grok":"PASS","gpt_codex":"PASS","claude":"PASS"}
    if action != "PASS": votes["grok"] = action
    return {"action":action,"votes":votes}

def make_router(model_action="PASS", council_action="PASS", events=None):
    audit = events if events is not None else []
    judge = ComposedHeavyJudge(backend=Backend(model_action), behavioral_judge=HeavyJudge(),
                               evidence_sink=audit.append)
    return SmartProviderRouter(TokenManager(),council_adapter=lambda _payload:council(council_action),
                               judge=judge), audit

def successful_ack(event):
    return {"status":"APPENDED","verified":True,"event_hash":event["event_hash"],
            "task_id":event["task_id"],"output_hash":event["output_hash"],
            "ledger_event_hash":"ledger-sha256:test","signature":"test-signature"}

def invoke(router, *, proof=None, evidence=None):
    return router.consume_with_routing(12,"Explain the sky.",context="general",
        authorization_proof=proof or gate_proof(),verification_key=KEY,task_id="task-1",
        owner_id="owner",required_scope=("repo/",),evidence_sink=evidence or successful_ack,now=200)

def test_router_releases_only_after_composed_judge_and_verifiable_append():
    router, events=make_router()
    result=invoke(router,evidence=lambda event:(events.append(event) or successful_ack(event)))
    assert result["status"] == "PASS"
    assert result["used_judge"] is True
    assert result["output_hash"] == "sha3-512:"+hashlib.sha3_512(result["output"].encode()).hexdigest()
    assert result["judge_verdict"]["candidate_hash"] == result["output_hash"]
    assert result["judge_verdict"]["task_id"] == "task-1"
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
    router,_=make_router()
    router.council_adapter=lambda _payload:{"action":"PASS","votes":{"grok":"PASS"}}
    with pytest.raises(RuntimeError,match="three lanes"): invoke(router)

def test_judge_backend_cannot_equal_provider_identity():
    judge=ComposedHeavyJudge(backend=Backend(),behavioral_judge=HeavyJudge(),evidence_sink=lambda _e:None)
    with pytest.raises(ValueError,match="independent"):
        judge.assert_independent(("independent-judge",))

def test_missing_judge_fails_closed_at_construction():
    with pytest.raises(TypeError,match="ComposedHeavyJudge"):
        SmartProviderRouter(TokenManager(),council_adapter=lambda _p:council(),judge=None)

def test_release_receipt_missing_signature_binding_fails_closed():
    router,_=make_router()
    def unverified(event):
        return {"status":"APPENDED","verified":True,"event_hash":event["event_hash"],
                "task_id":event["task_id"],"output_hash":event["output_hash"]}
    with pytest.raises(ReleaseIntegrityError,match="signed SCAR"):
        invoke(router,evidence=unverified)
