"""Evidence adapter for existing SCAR and REPMHL implementations.

SCAR is mandatory for an execution receipt: a missing or failed audit sink is a
hard error. REPMHL remains an injected secondary binding and never replaces SCAR.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from sovereign.scar.ledger import EventClass, SCARActor, SCARLedger

from .execution_contracts import ExecutionReceipt, RouteDecision, make_scar_event


class EvidenceWriteError(RuntimeError):
    """Raised when required evidence cannot be committed."""


class SCARLedgerSink:
    """Adapt public-safe coordination events to the canonical signed SCAR ledger."""

    def __init__(self, ledger: SCARLedger) -> None:
        if not isinstance(ledger, SCARLedger):
            raise TypeError("ledger must be the canonical SCARLedger")
        self._ledger = ledger

    def __call__(self, event: dict[str, Any]) -> Any:
        if not isinstance(event, dict):
            raise TypeError("SCAR evidence event must be a mapping")
        required = ("event_hash", "task_id", "output_hash")
        if any(not event.get(key) for key in required):
            raise ValueError("SCAR release event requires event_hash, task_id, and output_hash")
        route_trace = {
            key: event[key]
            for key in ("route", "mode", "decision", "policy_hash", "authorization", "output_hash", "judge_id")
            if event.get(key) is not None
        }
        metadata = {
            "task_id": str(event["task_id"]),
            "release_event_hash": str(event["event_hash"]),
            "evidence": {key: value for key, value in event.items() if key != "event_hash"},
        }
        stored = self._ledger.append_event(
            str(event.get("what", event.get("event", "AUDIT_EVENT"))),
            actor=SCARActor.DEVICE,
            event_class=EventClass.AUDIT,
            route_trace=route_trace,
            metadata=metadata,
            timestamp=str(event.get("when", event.get("timestamp", ""))) or None,
        )
        if not self._ledger.verify_chain():
            raise EvidenceWriteError("SCAR chain failed verification after append")
        return {
            "status": "APPENDED",
            "verified": True,
            "event_hash": str(event["event_hash"]),
            "task_id": str(event["task_id"]),
            "output_hash": str(event["output_hash"]),
            "ledger_event_hash": stored.event_hash,
            "signature": stored.signature,
            "sequence": stored.sequence,
        }


class EvidenceAdapter:
    """Bind receipts to existing SCAR and optional REPMHL stores."""

    def __init__(self, *, append_scar: Callable[[dict[str, Any]], Any], record_repmhl: Callable[[dict[str, Any]], Any] | None = None) -> None:
        if not callable(append_scar):
            raise TypeError("append_scar must be callable; evidence cannot be disabled")
        if record_repmhl is not None and not callable(record_repmhl):
            raise TypeError("record_repmhl must be callable when provided")
        self._append_scar = append_scar
        self._record_repmhl = record_repmhl

    def record(self, receipt: ExecutionReceipt, route: RouteDecision) -> dict[str, Any]:
        if receipt.task_id != route.task_id:
            raise ValueError("receipt and route task_id do not match")
        if receipt.mode != route.mode:
            raise ValueError("receipt and route modes do not match")
        if route.decision != "ALLOW":
            raise PermissionError("evidence requires an ALLOW route decision")
        event = make_scar_event(
            task_id=receipt.task_id,
            event="EXECUTION_RECEIPT",
            route=receipt.route,
            mode=receipt.mode,
            decision=route.decision,
            policy_hash=route.policy_hash,
            receipt_hash=receipt.receipt_hash,
        )
        try:
            ack = self._append_scar(event)
        except Exception as exc:
            raise EvidenceWriteError("SCAR append failed; protected workflow must stop") from exc
        if not isinstance(ack, Mapping) or ack.get("verified") is not True:
            raise EvidenceWriteError("SCAR append lacks a verified acknowledgment")
        if ack.get("event_hash") != event.get("event_hash"):
            raise EvidenceWriteError("SCAR append acknowledgment event hash mismatch")
        if self._record_repmhl is not None:
            try:
                self._record_repmhl({
                    "task_id": receipt.task_id,
                    "receipt_hash": receipt.receipt_hash,
                    "event_hash": event["event_hash"],
                    "route": receipt.route,
                    "mode": receipt.mode,
                })
            except Exception as exc:
                raise EvidenceWriteError("REPMHL binding failed after SCAR append; protected workflow must stop") from exc
        return event
