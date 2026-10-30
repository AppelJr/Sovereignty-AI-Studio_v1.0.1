# Appel420(root) | GPT-6 (OpenAI) | WHAT: added signed device-bound certification and quarantine engine | WHEN: 2026-10-30 | WHERE: backend/certification/engine.py | WHY: enforce evidence-backed model admission
from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

REQUIRED_CHECKS = frozenset({
    "identity",
    "authorization",
    "policy",
    "runtime",
    "integrity",
    "dependency",
    "adversarial",
    "data_boundary",
    "provenance",
    "device_attestation",
})
ALLOWED_CHECK_RESULTS = frozenset({"PASS", "FAIL", "NOT_RUN", "BLOCKED", "STALE"})
DEFAULT_SIGNATURE_ALGORITHMS = frozenset({"ML-DSA-87"})


class LedgerIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CertificationResult:
    status: str
    subject_id: str
    device_id: str
    artifact_sha256: str
    reason: str
    evaluated_at: str
    event_hash: str | None = None

    @property
    def admitted(self) -> bool:
        return self.status == "CERTIFIED"


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _utc(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _b64(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} required")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field} must be valid base64") from exc


class CertificationLedger:
    """Append-only SHA3-512 hash-chained certification decisions."""

    _thread_lock = threading.RLock()

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _read_verified(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        previous = "0" * 128
        events: list[dict[str, Any]] = []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
            for expected_seq, line in enumerate(lines, start=1):
                if not line:
                    continue
                event = json.loads(line)
                supplied_hash = event.pop("hash")
                if event.get("seq") != expected_seq or event.get("prev_hash") != previous:
                    raise LedgerIntegrityError("certification ledger sequence or link mismatch")
                calculated = hashlib.sha3_512(_canonical(event)).hexdigest()
                if not isinstance(supplied_hash, str) or supplied_hash != calculated:
                    raise LedgerIntegrityError("certification ledger digest mismatch")
                event["hash"] = supplied_hash
                events.append(event)
                previous = supplied_hash
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LedgerIntegrityError("certification ledger unreadable or malformed") from exc
        return events

    def verify_chain(self) -> dict[str, Any]:
        events = self._read_verified()
        return {
            "ok": True,
            "count": len(events),
            "root": events[-1]["hash"] if events else "0" * 128,
        }

    def append(self, event: Mapping[str, Any]) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._thread_lock:
            lock_path = self.path.with_suffix(self.path.suffix + ".lock")
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                events = self._read_verified()
                previous = events[-1]["hash"] if events else "0" * 128
                body = {
                    "seq": len(events) + 1,
                    "prev_hash": previous,
                    **dict(event),
                }
                digest = hashlib.sha3_512(_canonical(body)).hexdigest()
                line = _canonical({**body, "hash": digest}) + b"\n"
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try:
                    written = os.write(fd, line)
                    if written != len(line):
                        raise OSError("short certification ledger write")
                    os.fsync(fd)
                finally:
                    os.close(fd)
                return digest
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)

    def latest(self, subject_id: str, device_id: str) -> dict[str, Any] | None:
        events = self._read_verified()
        for event in reversed(events):
            if event.get("subject_id") == subject_id and event.get("device_id") == device_id:
                return event
        return None

    def is_admitted(self, subject_id: str, device_id: str, artifact_sha256: str) -> bool:
        try:
            event = self.latest(subject_id, device_id)
        except LedgerIntegrityError:
            return False
        return bool(
            event
            and event.get("status") == "CERTIFIED"
            and event.get("artifact_sha256") == artifact_sha256
        )


class CertificationEngine:
    """Issue a certification decision only after signed evidence verification."""

    def __init__(
        self,
        ledger: CertificationLedger,
        *,
        attestation_verifier: Callable[[str, bytes, bytes, bytes], bool] | None,
        owner_approval_verifier: Callable[[str, bytes, bytes], bool] | None,
        allowed_algorithms: frozenset[str] = DEFAULT_SIGNATURE_ALGORITHMS,
        max_age: timedelta = timedelta(hours=24),
    ):
        self.ledger = ledger
        self.attestation_verifier = attestation_verifier
        self.owner_approval_verifier = owner_approval_verifier
        self.allowed_algorithms = allowed_algorithms
        self.max_age = max_age

    def evaluate(
        self,
        record: Mapping[str, Any],
        *,
        expected_device_id: str,
        now: datetime | None = None,
    ) -> CertificationResult:
        instant = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        evaluated_at = instant.isoformat()
        subject_id = str(record.get("subject_id", ""))
        device_id = str(record.get("device_id", ""))
        artifact_hash = str(record.get("artifact_sha256", "")).lower()
        status = "NOT_CERTIFIED"
        reason = "evidence incomplete"

        def finish(final_status: str, final_reason: str) -> CertificationResult:
            event = {
                "event_type": "certification_decision",
                "subject_id": subject_id or "UNKNOWN",
                "device_id": device_id or "UNKNOWN",
                "artifact_sha256": artifact_hash,
                "status": final_status,
                "reason": final_reason,
                "evaluated_at": evaluated_at,
                "policy_version": str(record.get("policy_version", "unknown")),
            }
            try:
                event_hash = self.ledger.append(event)
            except (OSError, LedgerIntegrityError):
                return CertificationResult(
                    "NOT_CERTIFIED", subject_id, device_id, artifact_hash,
                    "evidence ledger write or integrity verification failed", evaluated_at
                )
            return CertificationResult(
                final_status, subject_id, device_id, artifact_hash,
                final_reason, evaluated_at, event_hash
            )

        if not subject_id or not device_id or device_id != expected_device_id:
            return finish("QUARANTINED", "subject or device identity mismatch")
        if not re.fullmatch(r"[0-9a-f]{64}", artifact_hash):
            return finish("QUARANTINED", "artifact SHA-256 is invalid")
        checks = record.get("checks")
        if not isinstance(checks, Mapping):
            return finish("NOT_CERTIFIED", "required test evidence missing")
        failed = sorted(k for k in REQUIRED_CHECKS if checks.get(k) == "FAIL")
        if failed:
            return finish("QUARANTINED", "required checks failed: " + ",".join(failed))
        missing = sorted(k for k in REQUIRED_CHECKS if checks.get(k) != "PASS")
        if missing:
            return finish("NOT_CERTIFIED", "required checks not passed: " + ",".join(missing))
        if self.attestation_verifier is None or self.owner_approval_verifier is None:
            return finish("NOT_CERTIFIED", "production signature verifiers are not configured")

        try:
            issued = _utc(record.get("issued_at"))
            expires = _utc(record.get("expires_at"))
            if issued > instant + timedelta(minutes=2):
                return finish("QUARANTINED", "evidence issued in the future")
            if expires <= instant:
                return finish("NOT_CERTIFIED", "certification evidence expired")
            if instant - issued > self.max_age:
                return finish("NOT_CERTIFIED", "certification evidence is stale")
            nonce = str(record.get("nonce", ""))
            if not re.fullmatch(r"[0-9a-fA-F]{64,128}", nonce):
                return finish("QUARANTINED", "attestation nonce invalid")
            algorithm = str(record.get("algorithm", ""))
            if algorithm not in self.allowed_algorithms:
                return finish("QUARANTINED", "signature algorithm not approved")
            public_key = _b64(record.get("public_key"), "public_key")
            signature = _b64(record.get("signature"), "signature")
            owner_signature = _b64(record.get("owner_signature"), "owner_signature")
            approval_id = str(record.get("owner_approval_id", ""))
            if not approval_id:
                return finish("NOT_CERTIFIED", "explicit owner approval missing")
            payload = _canonical({
                "subject_id": subject_id,
                "device_id": device_id,
                "artifact_sha256": artifact_hash,
                "policy_version": str(record.get("policy_version", "")),
                "checks": dict(checks),
                "issued_at": issued.isoformat(),
                "expires_at": expires.isoformat(),
                "nonce": nonce,
                "owner_approval_id": approval_id,
            })
            if not self.attestation_verifier(algorithm, public_key, payload, signature):
                return finish("QUARANTINED", "device attestation signature invalid")
            if not self.owner_approval_verifier(approval_id, payload, owner_signature):
                return finish("QUARANTINED", "owner approval signature invalid")
        except (ValueError, TypeError, OverflowError):
            return finish("QUARANTINED", "certification evidence malformed")
        return finish("CERTIFIED", "all required evidence verified")
