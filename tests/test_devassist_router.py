"""Tests for the DevAssist420 coordination core."""
from __future__ import annotations

import pytest

from backend.coordination import (
    BranchRegistry,
    ConflictManager,
    CouncilResult,
    DevAssistRouter,
    TaskEnvelope,
)


def test_task_envelope_requires_core_fields():
    with pytest.raises(ValueError):
        TaskEnvelope(task_id="", requester="x", owner="y")


def test_task_envelope_rejects_main_branch():
    with pytest.raises(ValueError):
        TaskEnvelope(task_id="t1", requester="r", owner="o", branch="main")


def test_branch_registry_protects_collaboration():
    registry = BranchRegistry()
    assert registry.is_owner_controlled("Collaboration")
    with pytest.raises(ValueError):
        registry.is_writable("Collaboration")


def test_conflict_manager_blocks_overlapping_scopes():
    cm = ConflictManager()
    a = TaskEnvelope(task_id="a", requester="r", owner="o", scope=("backend/api",))
    b = TaskEnvelope(task_id="b", requester="r", owner="o", scope=("backend/api/router.py",))
    assert cm.register(a) is None
    conflict = cm.register(b)
    assert conflict is not None
    assert "a" in conflict.conflicts_with


def test_router_classifies_and_routes():
    router = DevAssistRouter()
    envelope = router.classify(
        task_id="t1",
        requester="owner",
        owner="Appel420",
        scope=("routing", "coordination"),
    )
    assert envelope.branch == "devassist420"
    result = router.route(envelope)
    assert result.approved is True
    assert result.routes[0].branch == "devassist420"
    router.release(envelope.task_id)


def test_router_denies_protected_branch():
    router = DevAssistRouter()
    envelope = router.classify(
        task_id="t2",
        requester="owner",
        owner="Appel420",
        scope=("architecture",),
        branch="Collaboration",
    )
    result = router.route(envelope)
    assert result.approved is False
