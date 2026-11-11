from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import hashlib

import pytest

from backend.coordination.yank_procedural_review import (
    YANKEvidenceError,
    YANKProceduralReviewService,
    YANKReviewConflict,
    YANKReviewDenied,
)


class Harness:
    def __init__(self, path: Path):
        self.events = []
        self.fail_evidence = False
        self.participants = {"challenger-1", "challenger-2"}
        self.reviewers = {"reviewer-1"}
        self.service = self.make_service(path)

    def sink(self, event):
        if self.fail_evidence:
            raise OSError("SCAR unavailable")
        self.events.append(dict(event))
        n = len(self.events) - 1
        return SimpleNamespace(
            event_type=event["event"],
            event_id=f"event-{n}",
            event_hash=hashlib.sha256(f"event-{n}".encode()).hexdigest(),
            signature=f"signature-{n}",
            sequence=n,
        )

    def make_service(self, path):
        return YANKProceduralReviewService(
            path,
            evidence_sink=self.sink,
            participant_check=lambda actor, _arb: actor in self.participants,
            reviewer_check=lambda actor, _arb, challenger, initiators: (
                actor in self.reviewers and actor != challenger and actor not in initiators
            ),
            rerun_authorizer=lambda actor, _arb, _task: actor == "owner-1",
        )

    def create(self):
        return self.service.create_yank_arbitration(
            arbitration_id="arb-1",
            task_id="task-1",
            initiator_ids=("judge:model-1",),
            candidate_hash="sha3-512:" + "a" * 128,
        )

    def challenge(self, **overrides):
        values = {
            "challenger_id": "challenger-1",
            "defect_category": "OMITTED_EVIDENCE",
            "description": "Evidence reference E-17 was omitted from the original review.",
            "evidence_refs": ("evidence:E-17",),
        }
        values.update(overrides)
        return self.service.file_challenge("arb-1", **values)

    def review(self, **overrides):
        values = {
            "reviewer_id": "reviewer-1",
            "finding": "SUBSTANTIATED",
            "rationale": "The referenced evidence was available before the original decision.",
            "evidence_refs": ("evidence:E-17", "review:independent-check"),
        }
        values.update(overrides)
        return self.service.review_challenge("arb-1", **values)


def test_yank_registration_requires_attributable_initiator_and_sha3_hash(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    with pytest.raises(ValueError, match="initiator"):
        h.service.create_yank_arbitration(
            arbitration_id="arb-x", task_id="task-x", initiator_ids=(),
            candidate_hash="sha3-512:" + "a" * 128,
        )
    with pytest.raises(ValueError, match="sha3-512"):
        h.service.create_yank_arbitration(
            arbitration_id="arb-x", task_id="task-x", initiator_ids=("judge-1",),
            candidate_hash="not-a-digest",
        )
    with pytest.raises(YANKReviewDenied, match="only available for YANK"):
        h.service.create_yank_arbitration(
            arbitration_id="arb-x", task_id="task-x", initiator_ids=("judge-1",),
            candidate_hash="sha3-512:" + "a" * 128, original_action="PASS",
        )


def test_original_yank_initiator_cannot_challenge(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    h.create()
    with pytest.raises(YANKReviewDenied, match="cannot challenge"):
        h.challenge(challenger_id="judge:model-1")
    assert h.service.get_arbitration("arb-1")["state"] == "ESCROWED"


def test_unregistered_participant_is_denied(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    h.create()
    with pytest.raises(YANKReviewDenied, match="not a verified"):
        h.challenge(challenger_id="unknown-participant")


def test_challenge_requires_specific_category_and_evidence(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    h.create()
    with pytest.raises(ValueError, match="category"):
        h.challenge(defect_category="GENERAL_DISAGREEMENT")
    with pytest.raises(ValueError, match="evidence references"):
        h.challenge(evidence_refs=())
    assert h.service.get_arbitration("arb-1")["challenge_count"] == 0


def test_only_one_challenge_can_be_filed(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    h.create()
    h.challenge()
    with pytest.raises(YANKReviewConflict, match="one challenge"):
        h.challenge(challenger_id="challenger-2")
    assert h.service.get_arbitration("arb-1")["challenge_count"] == 1


def test_reviewer_must_be_independent_and_authorized(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    h.create()
    h.challenge()
    with pytest.raises(YANKReviewDenied, match="independent"):
        h.review(reviewer_id="challenger-1")
    with pytest.raises(YANKReviewDenied, match="not independently"):
        h.review(reviewer_id="untrusted-reviewer")
    assert h.service.get_arbitration("arb-1")["review_count"] == 0


def test_unsubstantiated_review_holds_for_human_and_blocks_rerun(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    h.create()
    h.challenge()
    result = h.review(finding="NOT_SUBSTANTIATED")
    assert result["state"] == "HELD_FOR_HUMAN_ESCALATION"
    with pytest.raises(YANKReviewConflict, match="substantiated"):
        h.service.rerun_original_arbitration(
            "arb-1", requester_id="owner-1", rerun_handler=lambda _snapshot: {"action": "PASS"}
        )


def test_substantiated_review_allows_exactly_one_original_rerun(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    h.create()
    h.challenge()
    h.review()
    calls = []

    def rerun(snapshot):
        calls.append(snapshot)
        assert snapshot["arbitration_id"] == "arb-1"
        assert snapshot["task_id"] == "task-1"
        assert snapshot["original_action"] == "YANK"
        return {"action": "PASS", "output_hash": "sha3-512:" + "b" * 128}

    result = h.service.rerun_original_arbitration(
        "arb-1", requester_id="owner-1", rerun_handler=rerun
    )
    assert result["state"] == "RESOLVED"
    assert result["rerun_count"] == 1
    assert result["output_released"] is False
    assert len(calls) == 1
    with pytest.raises(YANKReviewConflict, match="substantiated"):
        h.service.rerun_original_arbitration(
            "arb-1", requester_id="owner-1", rerun_handler=rerun
        )
    assert len(calls) == 1


def test_gate_authorization_is_required_before_rerun(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    h.create()
    h.challenge()
    h.review()
    with pytest.raises(YANKReviewDenied, match="Gate authorization"):
        h.service.rerun_original_arbitration(
            "arb-1", requester_id="not-owner", rerun_handler=lambda _snapshot: {"action": "PASS"}
        )
    assert h.service.get_arbitration("arb-1")["rerun_count"] == 0


def test_non_pass_rerun_escalates_without_repeating(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    h.create()
    h.challenge()
    h.review()
    result = h.service.rerun_original_arbitration(
        "arb-1", requester_id="owner-1", rerun_handler=lambda _snapshot: {"action": "YANK"}
    )
    assert result["state"] == "HELD_FOR_HUMAN_ESCALATION"
    assert result["rerun_count"] == 1


def test_rerun_handler_failure_consumes_budget_and_escalates(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    h.create()
    h.challenge()
    h.review()

    def fail(_snapshot):
        raise RuntimeError("provider detail must not leak")

    result = h.service.rerun_original_arbitration(
        "arb-1", requester_id="owner-1", rerun_handler=fail
    )
    assert result["state"] == "HELD_FOR_HUMAN_ESCALATION"
    assert result["rerun"]["action"] == "UNAVAILABLE"
    assert result["rerun"]["result"]["error_type"] == "RuntimeError"


def test_scar_failure_rolls_back_transition(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    h.create()
    h.fail_evidence = True
    with pytest.raises(YANKEvidenceError, match="rolled back"):
        h.challenge()
    assert h.service.get_arbitration("arb-1")["state"] == "ESCROWED"
    assert h.service.get_arbitration("arb-1")["challenge_count"] == 0


def test_state_survives_service_reopen_and_receipts_are_recorded(tmp_path):
    path = tmp_path / "review.sqlite3"
    h = Harness(path)
    h.create()
    h.challenge()
    h.review()
    h.service.close()
    h.service = h.make_service(path)
    state = h.service.get_arbitration("arb-1")
    assert state["state"] == "READY_FOR_RERUN"
    assert state["challenge_count"] == 1
    assert state["review_count"] == 1
    assert len(state["scar_receipts"]) == 3
    assert all(item["signature"] for item in state["scar_receipts"])


def test_event_receipt_rows_are_immutable(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    h.create()
    with pytest.raises(Exception, match="immutable SCAR receipt"):
        h.service._db.execute("DELETE FROM yank_scar_receipts")
    assert h.service.get_arbitration("arb-1")["state"] == "ESCROWED"


def test_arbitration_registration_is_idempotency_protected(tmp_path):
    h = Harness(tmp_path / "review.sqlite3")
    h.create()
    with pytest.raises(YANKReviewConflict, match="already exists"):
        h.create()
