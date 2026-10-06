"""
Door sign-off contract — PERSON + DEVICE + REQUEST + POLICY → SIGN-OFF.

Ceremony: READ → DISCUSS → IDENTIFY → SIGN-OFF

Invariants:
- Device identity proves which machine is at the door.
- Person identity proves which human is signing.
- Same device ≠ same authority.
- Device authentication never auto-authenticates the current person.
- Biometric unlocks the person credential; the cryptographic signature
  is the authorization evidence.
- IMEI is an identifier only — never a secret, never sole identity.
- SCAR records transitions; SCAR does not authorize.
- Unknown / incomplete → DENY (fail-closed).

This module is the contract and event shape. Cryptographic verify/sign
backends (ML-DSA, hardware keystore) plug in via SignVerifier protocol.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Optional, Protocol, Sequence


SCHEMA_VERSION = "1.0.0"
DOMAIN_SEPARATOR = "SCAR/DOOR_SIGNOFF/v1"


class ContractError(ValueError):
    """Malformed or incomplete contract. Callers must treat as DENY."""


class CeremonyPhase(str, Enum):
    READ = "READ"
    DISCUSS = "DISCUSS"
    IDENTIFY = "IDENTIFY"
    SIGN_OFF = "SIGN_OFF"


class DoorDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    DISCUSS = "DISCUSS"


class ScarEventType(str, Enum):
    DOOR_READ = "DOOR_READ"
    DOOR_DISCUSS = "DOOR_DISCUSS"
    DOOR_IDENTIFY = "DOOR_IDENTIFY"
    DOOR_SIGNOFF_REQUESTED = "DOOR_SIGNOFF_REQUESTED"
    DOOR_SIGNOFF_VERIFIED = "DOOR_SIGNOFF_VERIFIED"
    DOOR_SIGNOFF_DENIED = "DOOR_SIGNOFF_DENIED"
    DOOR_SIGNOFF_EXPIRED = "DOOR_SIGNOFF_EXPIRED"
    DOOR_OPERATION_RELEASED = "DOOR_OPERATION_RELEASED"


# ---------------------------------------------------------------------------
# Identity layers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeviceIdentity:
    """Which machine is at the door. Never implies person authority."""

    device_id: str
    device_public_key: str  # hex or base64url of enrolled device public key
    device_attestation: str  # attestation blob digest or structured claim ref
    imei: Optional[str] = None  # identifier only — not a secret, not sole identity
    hardware_backed: bool = False
    policy_epoch: int = 0

    def __post_init__(self) -> None:
        _require_nonempty(self.device_id, "device_id")
        _require_nonempty(self.device_public_key, "device_public_key")
        _require_nonempty(self.device_attestation, "device_attestation")


@dataclass(frozen=True)
class PersonIdentity:
    """Which human is signing. Independent of device identity."""

    person_id: str
    person_public_key: str  # enrolled person signing public key
    biometric_verified: bool = False  # unlock only; not authorization evidence
    session_binding: Optional[str] = None

    def __post_init__(self) -> None:
        _require_nonempty(self.person_id, "person_id")
        _require_nonempty(self.person_public_key, "person_public_key")


@dataclass(frozen=True)
class AuthorizationRequest:
    request_id: str
    scope: str
    policy_epoch: int
    expiry: float  # unix seconds absolute
    nonce: str
    operation: str
    created_at: float = field(default_factory=lambda: time.time())

    def __post_init__(self) -> None:
        _require_nonempty(self.request_id, "request_id")
        _require_nonempty(self.scope, "scope")
        _require_nonempty(self.nonce, "nonce")
        _require_nonempty(self.operation, "operation")
        if self.policy_epoch < 0:
            raise ContractError("policy_epoch must be >= 0")
        if self.expiry <= 0:
            raise ContractError("expiry must be a positive unix timestamp")


@dataclass(frozen=True)
class AuthorizationIdentity:
    """
    Authoritative identity tuple.

    AUTHORIZATION_IDENTITY =
        person_id + person_public_key
      + device_id + device_public_key + device_attestation
      + request_id + policy_epoch + scope + expiry + nonce
    """

    person: PersonIdentity
    device: DeviceIdentity
    request: AuthorizationRequest

    def canonical_dict(self) -> dict[str, Any]:
        """Deterministic field set for hashing / signing."""
        return {
            "schema_version": SCHEMA_VERSION,
            "domain": DOMAIN_SEPARATOR,
            "person_id": self.person.person_id,
            "person_public_key": self.person.person_public_key,
            "device_id": self.device.device_id,
            "device_public_key": self.device.device_public_key,
            "device_attestation": self.device.device_attestation,
            "imei": self.device.imei or "",
            "request_id": self.request.request_id,
            "policy_epoch": self.request.policy_epoch,
            "scope": self.request.scope,
            "expiry": self.request.expiry,
            "nonce": self.request.nonce,
            "operation": self.request.operation,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.canonical_dict()).encode("utf-8")

    def envelope_hash(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()

    def signing_message(self) -> bytes:
        """Domain-separated message the person key must sign."""
        body = self.canonical_bytes()
        return DOMAIN_SEPARATOR.encode("utf-8") + b"\n" + body


# ---------------------------------------------------------------------------
# Sign-off result + SCAR event shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignOffResult:
    decision: DoorDecision
    phase: CeremonyPhase
    identity: AuthorizationIdentity
    envelope_hash: str
    signature: Optional[str]  # base64url of person signature over signing_message
    signature_scheme: Optional[str]  # e.g. ML-DSA-65, Ed25519
    reason: str
    scar_event_type: ScarEventType
    timestamp: float = field(default_factory=lambda: time.time())

    def scar_event(
        self,
        *,
        prev_hash: str = "GENESIS",
        actor: str = "door",
        parent_event_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Immutable SCAR event shape for this door transition."""
        event_id = f"scar_{int(self.timestamp * 1_000_000)}_{secrets.token_hex(4)}"
        payload = {
            "event": self.scar_event_type.value,
            "event_version": 1,
            "schema_version": SCHEMA_VERSION,
            "event_id": event_id,
            "parent_event_id": parent_event_id,
            "timestamp": self.timestamp,
            "actor": actor,
            "phase": self.phase.value,
            "decision": self.decision.value,
            "reason": self.reason,
            "envelope_hash": self.envelope_hash,
            "person_id": self.identity.person.person_id,
            "device_id": self.identity.device.device_id,
            "request_id": self.identity.request.request_id,
            "scope": self.identity.request.scope,
            "policy_epoch": self.identity.request.policy_epoch,
            "operation": self.identity.request.operation,
            "signature_present": self.signature is not None,
            "signature_scheme": self.signature_scheme,
            # Digests only — never raw keys, biometrics, or private material
            "person_key_fingerprint": _fingerprint(self.identity.person.person_public_key),
            "device_key_fingerprint": _fingerprint(self.identity.device.device_public_key),
            "imei_present": self.identity.device.imei is not None,
            "biometric_verified": self.identity.person.biometric_verified,
            "hardware_backed": self.identity.device.hardware_backed,
            "prev": prev_hash,
        }
        payload["hash"] = _scar_hash(prev_hash, payload)
        return payload


# ---------------------------------------------------------------------------
# Verifier protocol (production backends plug in here)
# ---------------------------------------------------------------------------


class SignVerifier(Protocol):
    def verify(
        self,
        *,
        public_key: str,
        message: bytes,
        signature: str,
        scheme: str,
    ) -> bool:
        ...


# ---------------------------------------------------------------------------
# Door ceremony engine
# ---------------------------------------------------------------------------


class DoorSignOff:
    """
    Authorization door.

    Green button = sign-off ceremony, not login.
    AI may explain what is behind the door; only verified sign-off releases.
    """

    def __init__(
        self,
        *,
        verifier: Optional[SignVerifier] = None,
        clock: Optional[Callable[[], float]] = None,
        consumed_request_ids: Optional[set[str]] = None,
    ) -> None:
        self._verifier = verifier
        self._clock = clock or time.time
        self._consumed: set[str] = consumed_request_ids if consumed_request_ids is not None else set()
        self._phase: CeremonyPhase = CeremonyPhase.READ

    @property
    def phase(self) -> CeremonyPhase:
        return self._phase

    def mark_read(self) -> None:
        self._phase = CeremonyPhase.READ

    def mark_discuss(self) -> None:
        self._phase = CeremonyPhase.DISCUSS

    def mark_identify(self) -> None:
        self._phase = CeremonyPhase.IDENTIFY

    def evaluate(
        self,
        identity: AuthorizationIdentity,
        *,
        signature: Optional[str] = None,
        signature_scheme: Optional[str] = None,
        expected_policy_epoch: Optional[int] = None,
        allowed_scopes: Optional[Sequence[str]] = None,
    ) -> SignOffResult:
        """
        Run the sign-off checks. Fail-closed on any incomplete or invalid input.

        Order:
        1. structural identity
        2. request not expired
        3. request_id not replayed
        4. policy epoch
        5. scope
        6. person ≠ implied by device alone
        7. signature present + independent verify
        8. consume request_id
        """
        now = self._clock()
        env_hash = identity.envelope_hash()

        # Expiry
        if now > identity.request.expiry:
            return self._deny(
                identity,
                env_hash,
                reason="request_expired",
                scar_type=ScarEventType.DOOR_SIGNOFF_EXPIRED,
            )

        # Replay
        if identity.request.request_id in self._consumed:
            return self._deny(
                identity,
                env_hash,
                reason="request_id_replay",
                scar_type=ScarEventType.DOOR_SIGNOFF_DENIED,
            )

        # Policy epoch
        if expected_policy_epoch is not None:
            if identity.request.policy_epoch != expected_policy_epoch:
                return self._deny(
                    identity,
                    env_hash,
                    reason="policy_epoch_mismatch",
                    scar_type=ScarEventType.DOOR_SIGNOFF_DENIED,
                )
            if identity.device.policy_epoch != expected_policy_epoch:
                return self._deny(
                    identity,
                    env_hash,
                    reason="device_policy_epoch_mismatch",
                    scar_type=ScarEventType.DOOR_SIGNOFF_DENIED,
                )

        # Scope
        if allowed_scopes is not None and identity.request.scope not in allowed_scopes:
            return self._deny(
                identity,
                env_hash,
                reason="scope_not_allowed",
                scar_type=ScarEventType.DOOR_SIGNOFF_DENIED,
            )

        # Signature required for ALLOW
        if not signature or not signature_scheme:
            return self._deny(
                identity,
                env_hash,
                reason="signature_required",
                scar_type=ScarEventType.DOOR_SIGNOFF_DENIED,
            )

        if self._verifier is None:
            return self._deny(
                identity,
                env_hash,
                reason="verifier_not_configured",
                scar_type=ScarEventType.DOOR_SIGNOFF_DENIED,
            )

        message = identity.signing_message()
        ok = self._verifier.verify(
            public_key=identity.person.person_public_key,
            message=message,
            signature=signature,
            scheme=signature_scheme,
        )
        if not ok:
            return self._deny(
                identity,
                env_hash,
                reason="signature_verification_failed",
                scar_type=ScarEventType.DOOR_SIGNOFF_DENIED,
                signature=signature,
                signature_scheme=signature_scheme,
            )

        # Consume single-use request_id only after successful verify
        self._consumed.add(identity.request.request_id)
        self._phase = CeremonyPhase.SIGN_OFF

        return SignOffResult(
            decision=DoorDecision.ALLOW,
            phase=CeremonyPhase.SIGN_OFF,
            identity=identity,
            envelope_hash=env_hash,
            signature=signature,
            signature_scheme=signature_scheme,
            reason="signoff_verified",
            scar_event_type=ScarEventType.DOOR_SIGNOFF_VERIFIED,
            timestamp=now,
        )

    def discuss(
        self,
        identity: AuthorizationIdentity,
        *,
        reason: str = "further_discuss",
    ) -> SignOffResult:
        """DISCUSS is not ALLOW. Holds the door open for more evidence."""
        self._phase = CeremonyPhase.DISCUSS
        return SignOffResult(
            decision=DoorDecision.DISCUSS,
            phase=CeremonyPhase.DISCUSS,
            identity=identity,
            envelope_hash=identity.envelope_hash(),
            signature=None,
            signature_scheme=None,
            reason=reason,
            scar_event_type=ScarEventType.DOOR_DISCUSS,
        )

    def _deny(
        self,
        identity: AuthorizationIdentity,
        env_hash: str,
        *,
        reason: str,
        scar_type: ScarEventType,
        signature: Optional[str] = None,
        signature_scheme: Optional[str] = None,
    ) -> SignOffResult:
        return SignOffResult(
            decision=DoorDecision.DENY,
            phase=self._phase,
            identity=identity,
            envelope_hash=env_hash,
            signature=signature,
            signature_scheme=signature_scheme,
            reason=reason,
            scar_event_type=scar_type,
            timestamp=self._clock(),
        )


def fresh_nonce(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)


def fresh_request_id() -> str:
    return f"req_{int(time.time() * 1000)}_{secrets.token_hex(6)}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def canonical_json(obj: Mapping[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _require_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{field_name} must be a non-empty string")


def _fingerprint(material: str) -> str:
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _scar_hash(prev: str, payload: Mapping[str, Any]) -> str:
    """Hash chain link: sha512(prev || canonical_payload_without_hash)."""
    body = {k: v for k, v in payload.items() if k != "hash"}
    material = (prev + canonical_json(body)).encode("utf-8")
    return "sha512:" + hashlib.sha512(material).hexdigest()
