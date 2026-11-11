from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from sovereign.scar.durable import DurableSCARLedger, DurableSCARLedgerError
from sovereign.scar.ledger import EventClass, SCARActor


class HmacRoot:
    def __init__(self, key: bytes = b"unit-test-key-only") -> None:
        self.key = key

    def sign(self, payload: bytes) -> bytes:
        return hmac.new(self.key, payload, hashlib.sha256).digest()

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


def make_ledger(path: Path, root: HmacRoot | None = None) -> DurableSCARLedger:
    return DurableSCARLedger("test-ledger", "device:test", root or HmacRoot(), path)


def test_persistent_append_survives_reopen_and_verifies(tmp_path: Path) -> None:
    path = tmp_path / "scar" / "events.jsonl"
    ledger = make_ledger(path)
    first = ledger.append_event(
        "ROUTE_DECISION", actor=SCARActor.DEVICE, event_class=EventClass.ROUTING,
        capability_id="route.local", metadata={"decision": "allow"},
    )
    reopened = make_ledger(path)
    second = reopened.append_event(
        "REQUEST_DENIED", actor=SCARActor.SYSTEM, event_class=EventClass.SECURITY,
    )
    assert first.sequence == 0
    assert second.sequence == 1
    assert reopened.verify_chain()
    assert len(reopened.events) == 2


def test_signature_verifier_is_mandatory(tmp_path: Path) -> None:
    class SignOnly:
        def sign(self, payload: bytes) -> bytes:
            return b"x"
    with pytest.raises(DurableSCARLedgerError, match="verify is required"):
        DurableSCARLedger("test-ledger", "device:test", SignOnly(), tmp_path / "events.jsonl")


def test_tampered_payload_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    ledger = make_ledger(path)
    ledger.append_event("TEST", actor="device", event_class="system")
    row = json.loads(path.read_text().splitlines()[0])
    row["document"]["event_type"] = "FORGED"
    path.write_text(json.dumps(row) + "\n")
    with pytest.raises(DurableSCARLedgerError, match="event hash mismatch"):
        make_ledger(path)


def test_invalid_signature_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    ledger = make_ledger(path)
    ledger.append_event("TEST", actor="device", event_class="system")
    bad_root = HmacRoot(b"different-key")
    with pytest.raises(DurableSCARLedgerError, match="invalid signature"):
        make_ledger(path, bad_root)


def test_truncated_record_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b'{"record_version":1}')
    with pytest.raises(DurableSCARLedgerError, match="truncated"):
        make_ledger(path)


def test_symlink_ledger_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.jsonl"
    target.write_text("")
    link = tmp_path / "events.jsonl"
    link.symlink_to(target)
    with pytest.raises(DurableSCARLedgerError, match="symlink"):
        make_ledger(link)


def test_sequence_and_identity_are_bound(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    make_ledger(path).append_event("TEST", actor="device", event_class="system")
    with pytest.raises(DurableSCARLedgerError, match="identity mismatch"):
        DurableSCARLedger("test-ledger", "other-device", HmacRoot(), path)


def test_provider_requires_capability(tmp_path: Path) -> None:
    with pytest.raises(DurableSCARLedgerError, match="capability provenance"):
        make_ledger(tmp_path / "events.jsonl").append_event(
            "PROVIDER_CALL", actor="provider", event_class="ai_request",
        )
