"""Gate-issued authorization proofs for Genesis and Studio boundaries.

A plain mapping such as ``{\"decision\": \"OWNER_AUTHORIZED\", \"policy_hash\": \"...\"}``
is never authority. Downstream adapters must verify a Gate-signed proof that binds:

* owner identity
* device (optional but recorded)
* task_id
* scope
* policy_hash / policy version
* decision
* expiry
* evidence_sequence (SCAR binding)

HMAC-SHA256 is used for local/offline testability. Production may replace the
signer/verifier with ML-DSA-65 without changing the claim schema.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


PROOF_SCHEMA = "sovereignty.gate.authorization_proof.v1"
DOMAIN = b"sovereignty-gate-authorization-proof/v1\0"


class AuthorizationProofError(ValueError):
    """Raised when a Gate authorization proof is absent, invalid, or expired."""


@dataclass(frozen=True, slots=True)
class GateAuthorizationProof:
    """Verified claims extracted from a Gate-issued authorization proof."""

    proof_id: str
    owner_id: str
    device_id: str | None
    task_id: str
    scope: tuple[str, ...]
    decision: str
    policy_hash: str
    policy_version: str
    reason_code: str
    evidence_sequence: int | None
    expires_at: int
    issued_at: int

    def allows_decision(self, *accepted: str) -> bool:
        return self.decision in {item.upper() for item in accepted}

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "schema": PROOF_SCHEMA,
            "proof_id": self.proof_id,
            "owner_id": self.owner_id,
            "device_id": self.device_id,
            "task_id": self.task_id,
            "scope": list(self.scope),
            "decision": self.decision,
            "policy_hash": self.policy_hash,
            "policy_version": self.policy_version,
            "reason_code": self.reason_code,
            "evidence_sequence": self.evidence_sequence,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
        }


def _canonical_claims(claims: Mapping[str, Any]) -> bytes:
    return json.dumps(
        claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sign_payload(payload: bytes, secret: bytes) -> str:
    digest = hmac.new(secret, DOMAIN + payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _resolve_secret(secret: bytes | None) -> bytes:
    if secret is not None:
        if not secret:
            raise AuthorizationProofError("empty verification key")
        return secret
    raw = os.environ.get("SOVEREIGN_GATE_PROOF_KEY")
    if not raw:
        raise AuthorizationProofError("gate proof verification key unavailable")
    return raw.encode("utf-8")


def issue_gate_authorization_proof(
    *,
    proof_id: str,
    owner_id: str,
    task_id: str,
    scope: Sequence[str],
    decision: str,
    policy_hash: str,
    policy_version: str = "1",
    reason_code: str = "AUTHORIZED",
    device_id: str | None = None,
    evidence_sequence: int | None = None,
    issued_at: int | None = None,
    expires_at: int | None = None,
    ttl_seconds: int = 300,
    secret: bytes | None = None,
) -> str:
    """Issue a compact Gate authorization proof string (payload.signature)."""
    if not proof_id or not owner_id or not task_id:
        raise AuthorizationProofError("proof_id, owner_id, and task_id are required")
    if not policy_hash:
        raise AuthorizationProofError("policy_hash is required")
    decision_u = str(decision).upper()
    if decision_u not in {
        "ALLOW",
        "APPROVED",
        "OWNER_AUTHORIZED",
        "DELEGATED_AUTHORIZED",
        "OWNER_OVERRIDE",
        "DENY",
    }:
        raise AuthorizationProofError(f"unsupported decision: {decision}")

    now = int(time.time()) if issued_at is None else int(issued_at)
    exp = int(expires_at) if expires_at is not None else now + int(ttl_seconds)
    if exp <= now:
        raise AuthorizationProofError("expires_at must be after issued_at")

    claims: dict[str, Any] = {
        "schema": PROOF_SCHEMA,
        "proof_id": str(proof_id),
        "owner_id": str(owner_id),
        "device_id": str(device_id) if device_id else None,
        "task_id": str(task_id),
        "scope": [str(item) for item in scope],
        "decision": decision_u,
        "policy_hash": str(policy_hash),
        "policy_version": str(policy_version),
        "reason_code": str(reason_code),
        "evidence_sequence": evidence_sequence,
        "issued_at": now,
        "expires_at": exp,
    }
    payload = _canonical_claims(claims)
    key = _resolve_secret(secret)
    return f"{_b64url_encode(payload)}.{_sign_payload(payload, key)}"


def verify_gate_authorization_proof(
    proof: str | Mapping[str, Any] | object,
    *,
    secret: bytes | None = None,
    now: int | None = None,
    expected_task_id: str | None = None,
    required_scope: Sequence[str] | None = None,
) -> GateAuthorizationProof:
    """Verify a Gate proof string or an object that embeds ``gate_proof``.

    Forgeable dicts that only carry ``decision`` + ``policy_hash`` are rejected.
    """
    token = _extract_token(proof)
    if not token or "." not in token:
        raise AuthorizationProofError("missing or malformed gate authorization proof")

    encoded_payload, encoded_signature = token.split(".", 1)
    key = _resolve_secret(secret)

    try:
        payload = _b64url_decode(encoded_payload)
        expected = _sign_payload(payload, key)
        actual = encoded_signature
    except (ValueError, TypeError) as exc:
        raise AuthorizationProofError("invalid gate proof encoding") from exc

    if not hmac.compare_digest(expected, actual):
        raise AuthorizationProofError("invalid gate proof signature")

    try:
        claims = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorizationProofError("invalid gate proof payload") from exc

    if not isinstance(claims, dict):
        raise AuthorizationProofError("invalid gate proof claims")
    if claims.get("schema") != PROOF_SCHEMA:
        raise AuthorizationProofError("unsupported gate proof schema")

    required = {
        "proof_id",
        "owner_id",
        "task_id",
        "scope",
        "decision",
        "policy_hash",
        "policy_version",
        "reason_code",
        "issued_at",
        "expires_at",
    }
    if not required.issubset(claims):
        raise AuthorizationProofError("gate proof missing required claims")

    current = int(time.time()) if now is None else int(now)
    if int(claims["expires_at"]) <= current:
        raise AuthorizationProofError("gate proof expired")
    if not isinstance(claims["scope"], list):
        raise AuthorizationProofError("invalid scope claims")

    decision = str(claims["decision"]).upper()
    if decision in {"DENY", "DENIED"}:
        raise AuthorizationProofError("gate proof decision is deny")

    task_id = str(claims["task_id"])
    if expected_task_id is not None and task_id != expected_task_id:
        raise AuthorizationProofError("gate proof task_id mismatch")

    scope = tuple(str(item) for item in claims["scope"])
    if required_scope:
        missing = [item for item in required_scope if item not in scope]
        if missing:
            raise AuthorizationProofError(
                f"gate proof missing required scope: {','.join(missing)}"
            )

    evidence_sequence = claims.get("evidence_sequence")
    if evidence_sequence is not None:
        evidence_sequence = int(evidence_sequence)

    return GateAuthorizationProof(
        proof_id=str(claims["proof_id"]),
        owner_id=str(claims["owner_id"]),
        device_id=str(claims["device_id"]) if claims.get("device_id") else None,
        task_id=task_id,
        scope=scope,
        decision=decision,
        policy_hash=str(claims["policy_hash"]),
        policy_version=str(claims["policy_version"]),
        reason_code=str(claims["reason_code"]),
        evidence_sequence=evidence_sequence,
        expires_at=int(claims["expires_at"]),
        issued_at=int(claims["issued_at"]),
    )


def _extract_token(proof: str | Mapping[str, Any] | object) -> str:
    if isinstance(proof, str):
        return proof.strip()
    if isinstance(proof, Mapping):
        for key in ("gate_proof", "authorization_proof", "proof"):
            value = proof.get(key)
            if isinstance(value, str) and value:
                return value.strip()
        # Explicitly reject legacy forgeable shapes.
        if "decision" in proof and "policy_hash" in proof and "gate_proof" not in proof:
            raise AuthorizationProofError(
                "forgeable authorization mapping rejected; gate_proof required"
            )
        raise AuthorizationProofError("authorization object lacks gate_proof")
    token = getattr(proof, "gate_proof", None)
    if isinstance(token, str) and token:
        return token.strip()
    raise AuthorizationProofError("unsupported authorization proof type")
