"""Adapter-boundary tests for Genesis, DevAssist, and evidence."""
from __future__ import annotations

import pytest

from backend.coordination.devassist_adapter import DevAssistExecutionAdapter
from backend.coordination.evidence_adapter import (
    EvidenceAdapter,
    EvidenceWriteError,
    SCARLedgerSink,
)
from backend.coordination.genesis_adapter import GenesisRouterAdapter
from backend.coordination.task_envelope import TaskEnvelope
from sovereign.scar.ledger import EventClass, SCARActor, SCARLedger


class TestRoot:
    def sign(self, payload: bytes) -> bytes:
        return payload[:32]


def task(mode: str = "offline") -> TaskEnvelope:
    return TaskEnvelope("task-1", "owner", "owner", scope=("repo/",), mode=mode)


def approved(mode: str = "offline") -> dict[str, str]:
    return {"decision": "OWNER_AUTHORIZED", "policy_hash": "sha256:policy"}


def test_genesis_does_not_route_denied_work() -> None:
    with pytest.raises(PermissionError):
        GenesisRouterAdapter().decide(task(), {"decision": "DENY", "policy_hash": "sha256:p"})


def test_genesis_routes_by_mode_without_executing() -> None:
    route = GenesisRouterAdapter().decide(task(), approved())
    assert route.route == "devassist"
    assert route.decision == "ALLOW"


def test_devassist_requires_authorized_local_route() -> None:
    adapter = DevAssistExecutionAdapter(lambda _task, _route: {"status": "COMPLETED"})
    route = GenesisRouterAdapter().decide(task(), approved())
    receipt = adapter.execute(task(), route)
    assert receipt.status == "COMPLETED"
    assert receipt.network_accessed is False


def test_devassist_rejects_scope_or_route_mismatch() -> None:
    adapter = DevAssistExecutionAdapter(lambda _task, _route: {"status": "COMPLETED"})
    route = GenesisRouterAdapter().decide(task(), approved())
    other = TaskEnvelope("task-2", "owner", "owner", mode="offline")
    with pytest.raises(ValueError, match="task_id"):
        adapter.execute(other, route)


def test_evidence_adapter_delegates_to_existing_stores() -> None:
    scar_events: list[dict] = []
    repmhl_records: list[dict] = []
    adapter = DevAssistExecutionAdapter(lambda _task, _route: {"status": "COMPLETED"})
    route = GenesisRouterAdapter().decide(task(), approved())
    receipt = adapter.execute(task(), route)
    event = EvidenceAdapter(
        append_scar=scar_events.append,
        record_repmhl=repmhl_records.append,
    ).record(receipt, route)
    assert scar_events == [event]
    assert repmhl_records[0]["receipt_hash"] == receipt.receipt_hash


def test_evidence_sink_is_required() -> None:
    with pytest.raises(TypeError, match="append_scar"):
        EvidenceAdapter(append_scar=None)  # type: ignore[arg-type]


def test_scar_sink_writes_to_canonical_ledger() -> None:
    ledger = SCARLedger("device:test", TestRoot())
    adapter = DevAssistExecutionAdapter(lambda _task, _route: {"status": "COMPLETED"})
    route = GenesisRouterAdapter().decide(task(), approved())
    receipt = adapter.execute(task(), route)
    event = EvidenceAdapter(append_scar=SCARLedgerSink(ledger)).record(receipt, route)
    assert len(ledger.events) == 1
    stored = ledger.events[0]
    assert stored.event_type == "EXECUTION_RECEIPT"
    assert stored.actor is SCARActor.DEVICE
    assert stored.event_class is EventClass.AUDIT
    assert stored.metadata["task_id"] == "task-1"
    assert stored.metadata["event_hash"] == event["event_hash"]
    assert ledger.verify_chain()


def test_scar_append_failure_fails_closed() -> None:
    adapter = DevAssistExecutionAdapter(lambda _task, _route: {"status": "COMPLETED"})
    route = GenesisRouterAdapter().decide(task(), approved())
    receipt = adapter.execute(task(), route)

    def fail(_event: dict) -> None:
        raise OSError("disk full")

    with pytest.raises(EvidenceWriteError, match="SCAR append failed"):
        EvidenceAdapter(append_scar=fail).record(receipt, route)


def test_repmhl_failure_fails_closed_after_scar_write() -> None:
    scar_events: list[dict] = []
    adapter = DevAssistExecutionAdapter(lambda _task, _route: {"status": "COMPLETED"})
    route = GenesisRouterAdapter().decide(task(), approved())
    receipt = adapter.execute(task(), route)

    def fail(_event: dict) -> None:
        raise OSError("repmhl unavailable")

    with pytest.raises(EvidenceWriteError, match="REPMHL binding failed"):
        EvidenceAdapter(append_scar=scar_events.append, record_repmhl=fail).record(receipt, route)
    assert len(scar_events) == 1
