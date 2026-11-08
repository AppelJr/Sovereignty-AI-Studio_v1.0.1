from __future__ import annotations

import hashlib
import pytest

from sovereign_core.chain_of_command import (
    AuthorizationRequired, ChainOfCommand, ChainRequest, EvidenceWriteError,
)


class Judge:
    def __init__(self, action="PASS"):
        self.action = action
    def review(self, *, original_output, context, force_judge):
        assert force_judge is True
        return {"final_output": original_output, "verdict": {"action": self.action}}


def lanes(recommendation="PASS"):
    return {
        name: (lambda payload, n=name: {
            "output": payload["previous_output"] or f"{n} candidate",
            "recommendation": recommendation,
            "confidence": 0.9,
            "rationale": "fixture",
        })
        for name in ("grok", "gpt_codex", "claude")
    }


def build(*, judge_action="PASS", recommendation="PASS", evidence=None,
          rewrite=None, release=None, verifier=None):
    events = [] if evidence is None else evidence
    return ChainOfCommand(
        owner_authorizer=lambda _req: {"decision": "ALLOW", "gate_proof": "signed-proof"},
        authorization_verifier=verifier or (
            lambda _proof, req: {"owner_id": req.owner_id, "task_id": req.request_id,
                                 "decision": "OWNER_AUTHORIZED", "proof_id": "p1"}
        ),
        release_verifier=release or (lambda _claims, _req, output, digest: (
            digest == "sha3-512:" + hashlib.sha3_512(output.encode()).hexdigest()
        )),
        route_selector=lambda _req: {"selected_lanes": ["grok", "gpt_codex", "claude"]},
        lane_adapters=lanes(recommendation),
        judge=Judge(judge_action),
        evidence_sink=events.append,
        rewrite_handler=rewrite,
        max_rewrites=1,
    ), events


def test_pass_requires_all_three_lanes_and_both_gates():
    chain, events = build()
    result = chain.run(ChainRequest("r1", "owner", "prompt"))
    assert result.status == "PASS"
    assert result.output_hash.startswith("sha3-512:")
    assert events[-1]["what"] == "OUTENV_RELEASED"


def test_missing_gate_proof_is_denied():
    chain, _ = build()
    chain._authorize = lambda _req: {"decision": "ALLOW"}
    with pytest.raises(AuthorizationRequired, match="proof"):
        chain.run(ChainRequest("r2", "owner", "prompt"))


def test_cryptographic_verifier_failure_blocks_routing():
    def fail(_proof, _req):
        raise ValueError("bad signature")
    chain, _ = build(verifier=fail)
    with pytest.raises(AuthorizationRequired, match="verification failed"):
        chain.run(ChainRequest("r3", "owner", "prompt"))


def test_yank_escrows_and_withholds_output():
    chain, events = build(judge_action="YANK")
    result = chain.run(ChainRequest("r4", "owner", "prompt"))
    assert result.status == "ESCROW_PENDING_REVIEW"
    assert result.output is None
    assert events[-1]["what"] == "ESCROW_PENDING_REVIEW"


def test_rewrite_candidate_is_reprocessed_before_pass():
    def dynamic_lanes():
        def lane(payload, name):
            revised = payload["previous_output"] is not None
            return {"output": payload["previous_output"] or f"{name} initial",
                    "recommendation": "PASS" if revised else "REWRITE",
                    "confidence": 0.9}
        return {name: (lambda p, n=name: lane(p, n))
                for name in ("grok", "gpt_codex", "claude")}
    chain, _ = build(rewrite=lambda _payload: "revised candidate")
    chain._lanes = dynamic_lanes()
    result = chain.run(ChainRequest("r5", "owner", "prompt"))
    assert result.status == "PASS"
    assert result.attempts == 2
    assert result.output == "revised candidate"


def test_release_gate_failure_blocks_output():
    def fail(_claims, _req, _output, _digest):
        raise PermissionError("release denied")
    chain, _ = build(release=fail)
    with pytest.raises(EvidenceWriteError, match="post-judge release gate"):
        chain.run(ChainRequest("r6", "owner", "prompt"))


def test_evidence_sink_failure_blocks_output():
    def fail(_event):
        raise OSError("disk full")
    chain, _ = build(evidence=[])
    chain._evidence = fail
    with pytest.raises(EvidenceWriteError, match="evidence write failed"):
        chain.run(ChainRequest("r7", "owner", "prompt"))
