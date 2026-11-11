"""Durable, signature-verified SCAR JSONL ledger.

The existing in-memory SCARLedger remains source-compatible. This class is the
persistent adapter: it serializes the same signed event document, verifies
every historical signature before append/read, and advances sequence only
after an fsynced append. Hash linkage is integrity evidence, not authorization.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Iterator, Mapping, Protocol
from uuid import uuid4

from .ledger import (
    EventClass,
    GENESIS_EVENT_HASH,
    SCARActor,
    SCAREvent,
    _hash_event,
    _signature_text,
    canonical_bytes,
)

RECORD_VERSION = 1


class SignatureVerifier(Protocol):
    def verify(self, payload: bytes, signature: bytes) -> bool: ...


class DurableSCARLedgerError(RuntimeError):
    """Raised when persistent SCAR state cannot be safely read or changed."""


def _signature_bytes(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise DurableSCARLedgerError("signature is not canonical hexadecimal") from exc


def _safe_path(path: Path) -> Path:
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise DurableSCARLedgerError("ledger path must be an absolute, non-root path")
    # Reject symlinks in every existing component before creating directories.
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise DurableSCARLedgerError(f"symlink path component refused: {current}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or not path.parent.is_dir():
        raise DurableSCARLedgerError("ledger parent or file is unsafe")
    return path


class DurableSCARLedger:
    """Append-only persistent SCAR ledger with mandatory signature verification."""

    def __init__(
        self,
        ledger_id: str,
        identity_id: str,
        root_of_trust: Any,
        path: str | os.PathLike[str],
    ) -> None:
        if not ledger_id or not identity_id:
            raise ValueError("ledger_id and identity_id are required")
        if not callable(getattr(root_of_trust, "sign", None)):
            raise DurableSCARLedgerError("RootOfTrust.sign is required")
        if not callable(getattr(root_of_trust, "verify", None)):
            raise DurableSCARLedgerError("RootOfTrust.verify is required for durable mode")
        self.ledger_id = ledger_id
        self.identity_id = identity_id
        self.root_of_trust = root_of_trust
        self.path = _safe_path(Path(path).expanduser())
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        if self.lock_path.is_symlink():
            raise DurableSCARLedgerError("symlink lock file refused")
        self._load_verified()

    @contextmanager
    def _locked(self) -> Iterator[int]:
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.lock_path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise DurableSCARLedgerError("lock is not a regular file")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield fd
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _read_records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        if self.path.is_symlink() or not self.path.is_file():
            raise DurableSCARLedgerError("ledger must be a regular file")
        records: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as stream:
            for line_no, line in enumerate(stream, 1):
                if not line.endswith("\n") or not line.strip():
                    raise DurableSCARLedgerError(f"truncated or blank record at line {line_no}")
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise DurableSCARLedgerError(f"invalid JSON at line {line_no}") from exc
                if not isinstance(record, dict):
                    raise DurableSCARLedgerError(f"record {line_no} is not an object")
                records.append(record)
        return records

    def _verify_records(self, records: list[dict[str, Any]]) -> list[SCAREvent]:
        events: list[SCAREvent] = []
        previous = GENESIS_EVENT_HASH
        for sequence, record in enumerate(records):
            if record.get("record_version") != RECORD_VERSION:
                raise DurableSCARLedgerError(f"unsupported record version at sequence {sequence}")
            if record.get("ledger_id") != self.ledger_id:
                raise DurableSCARLedgerError(f"ledger identity mismatch at sequence {sequence}")
            document = record.get("document")
            signature = record.get("signature")
            event_hash = record.get("event_hash")
            if not isinstance(document, dict) or not isinstance(signature, str):
                raise DurableSCARLedgerError(f"malformed signed record at sequence {sequence}")
            if document.get("sequence") != sequence:
                raise DurableSCARLedgerError(f"sequence gap at sequence {sequence}")
            if document.get("identity_id") != self.identity_id:
                raise DurableSCARLedgerError(f"owner/device identity mismatch at sequence {sequence}")
            if document.get("previous_event_hash") != previous:
                raise DurableSCARLedgerError(f"previous hash mismatch at sequence {sequence}")
            expected_hash = _hash_event(document, signature)
            if event_hash != expected_hash:
                raise DurableSCARLedgerError(f"event hash mismatch at sequence {sequence}")
            try:
                verified = self.root_of_trust.verify(
                    canonical_bytes(document), _signature_bytes(signature)
                )
            except Exception as exc:
                raise DurableSCARLedgerError(
                    f"signature verification failed at sequence {sequence}"
                ) from exc
            if verified is not True:
                raise DurableSCARLedgerError(f"invalid signature at sequence {sequence}")
            try:
                event = SCAREvent(
                    sequence=sequence,
                    event_id=document["event_id"],
                    event_type=document["event_type"],
                    timestamp=document["timestamp"],
                    identity_id=document["identity_id"],
                    actor=SCARActor(document["actor"]),
                    capability_id=document.get("capability_id"),
                    memory_hash=document.get("memory_hash"),
                    event_class=EventClass(document["event_class"]),
                    route_trace=document.get("route_trace"),
                    classification_level=document.get("classification_level", 0),
                    previous_event_hash=previous,
                    signature=signature,
                    event_hash=event_hash,
                    metadata=document.get("metadata", {}),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise DurableSCARLedgerError(f"invalid event schema at sequence {sequence}") from exc
            events.append(event)
            previous = event_hash
        return events

    def _load_verified(self) -> list[SCAREvent]:
        with self._locked():
            return self._verify_records(self._read_records())

    @property
    def events(self) -> tuple[SCAREvent, ...]:
        return tuple(self._load_verified())

    def append_event(
        self,
        event_type: str,
        *,
        actor: SCARActor | str,
        event_class: EventClass | str,
        capability_id: str | None = None,
        memory_hash: str | None = None,
        route_trace: Mapping[str, Any] | None = None,
        classification_level: int = 0,
        metadata: Mapping[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> SCAREvent:
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("event_type must be a non-empty string")
        if not 0 <= classification_level <= 4:
            raise ValueError("classification_level must be between 0 and 4")
        normalized_actor = SCARActor(actor)
        normalized_class = EventClass(event_class)
        if normalized_actor is SCARActor.PROVIDER and not capability_id:
            raise DurableSCARLedgerError("Provider events require capability provenance")
        with self._locked():
            records = self._read_records()
            events = self._verify_records(records)
            previous = events[-1].event_hash if events else GENESIS_EVENT_HASH
            document: dict[str, Any] = {
                "sequence": len(events),
                "event_id": str(uuid4()),
                "event_type": event_type,
                "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
                "identity_id": self.identity_id,
                "actor": normalized_actor.value,
                "capability_id": capability_id,
                "memory_hash": memory_hash,
                "event_class": normalized_class.value,
                "previous_event_hash": previous,
                "metadata": dict(metadata or {}),
            }
            if route_trace is not None:
                document["route_trace"] = dict(route_trace)
            if classification_level:
                document["classification_level"] = classification_level
            payload = canonical_bytes(document)
            signature = _signature_text(self.root_of_trust.sign(payload))
            signature_bytes = _signature_bytes(signature)
            if self.root_of_trust.verify(payload, signature_bytes) is not True:
                raise DurableSCARLedgerError("RootOfTrust rejected its newly created signature")
            event_hash = _hash_event(document, signature)
            record = {
                "record_version": RECORD_VERSION,
                "ledger_id": self.ledger_id,
                "document": document,
                "signature": signature,
                "event_hash": event_hash,
            }
            encoded = canonical_bytes(record) + b"\n"
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, flags, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise DurableSCARLedgerError("ledger is not a regular file")
                written = os.write(fd, encoded)
                if written != len(encoded):
                    raise DurableSCARLedgerError("short write; append durability unproven")
                os.fsync(fd)
            finally:
                os.close(fd)
            dir_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            # Return only after the durable append and directory sync complete.
            return self._verify_records(records + [record])[-1]

    def verify_chain(self) -> bool:
        try:
            self._load_verified()
            return True
        except DurableSCARLedgerError:
            return False
