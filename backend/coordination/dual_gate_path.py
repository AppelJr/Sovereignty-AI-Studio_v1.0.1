"""Two-gate enforcement: authorization before routing, integrity before release."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Callable, Mapping

from backend.coordination.authorization_proof import (
    GateAuthorizationProof,
    verify_gate_authorization_proof,
)


class DualGateDenied(PermissionError):
    """Request denied at the authorization or release boundary."""


class ReleaseIntegrityError(RuntimeError):
    """Output failed post-execution integrity validation."""


@dataclass(frozen=True, slots=True)
class DualGateReceipt:
    task_id: str
    authorization_proof_id: str
    authorization_policy_hash: str
    output_hash: str
    output: str
    release_status: str
    evidence_event_hash: str


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _release_event_hash(event: Mapping[str, Any]) -> str:
    body = {key: value for key, value in event.items() if key != "event_hash"}
    return "sha3-512:" + hashlib.sha3_512(_canonical(body)).hexdigest()


def _require_verifiable_evidence(event: Mapping[str, Any], ack: Any) -> None:
    """Require a successful append receipt that binds the exact release event."""
    if not isinstance(ack, Mapping):
        raise ReleaseIntegrityError("release evidence append returned no verifiable receipt")
    if ack.get("verified") is not True:
        raise ReleaseIntegrityError("release evidence receipt is not verified")
    if str(ack.get("status", "")).upper() != "APPENDED":
        raise ReleaseIntegrityError("release evidence append was not acknowledged as APPENDED")
    for key in ("event_hash", "task_id", "output_hash"):
        if ack.get(key) != event.get(key):
            raise ReleaseIntegrityError(f"release evidence receipt {key} mismatch")
    if not ack.get("ledger_event_hash") or not ack.get("signature"):
        raise ReleaseIntegrityError("release evidence receipt lacks signed SCAR ledger binding")


def authorize_before_route(
    proof: str,
    *,
    verification_key: bytes,
    task_id: str,
    owner_id: str,
    required_scope: tuple[str, ...],
    now: int | None = None,
) -> GateAuthorizationProof:
    """Gate 1. Verify signed claims for owner, task, scope, decision, and expiry."""
    try:
        claims = verify_gate_authorization_proof(
            proof,
            secret=verification_key,
            now=now,
            expected_task_id=task_id,
            required_scope=required_scope,
        )
    except (ValueError, TypeError) as exc:
        raise DualGateDenied("pre-route Gate authorization failed") from exc
    if claims.owner_id != owner_id:
        raise DualGateDenied("pre-route owner identity mismatch")
    if not claims.allows_decision("ALLOW", "APPROVED", "OWNER_AUTHORIZED", "DELEGATED_AUTHORIZED", "OWNER_OVERRIDE"):
        raise DualGateDenied("pre-route Gate decision is not an allow")
    if not claims.policy_hash:
        raise DualGateDenied("pre-route Gate policy binding is missing")
    return claims


def verify_before_release(
    proof: GateAuthorizationProof,
    execution_result: Mapping[str, Any],
    *,
    expected_task_id: str,
    evidence_sink: Callable[[dict[str, Any]], Any],
    memory_loaded: bool = False,
    network_accessed: bool = False,
) -> DualGateReceipt:
    """Gate 2. Verify exact judge verdict, digest, and signed append receipt."""
    if proof.task_id != expected_task_id:
        raise DualGateDenied("release task does not match authorized task")
    if str(execution_result.get("status", "")).upper() != "PASS":
        raise DualGateDenied("only Heavy Judge PASS may reach OUTENV")
    output = execution_result.get("output")
    if not isinstance(output, str) or not output:
        raise ReleaseIntegrityError("PASS result has no output")
    digest = "sha3-512:" + hashlib.sha3_512(output.encode("utf-8")).hexdigest()
    if execution_result.get("output_hash") != digest:
        raise ReleaseIntegrityError("OUTENV digest mismatch")

    verdict = execution_result.get("judge_verdict")
    required_verdict = ("task_id", "candidate_hash", "policy_hash", "judge_id", "action")
    if not isinstance(verdict, Mapping) or any(not verdict.get(field) for field in required_verdict):
        raise ReleaseIntegrityError("independent judge verdict is missing required bindings")
    if verdict["task_id"] != expected_task_id:
        raise ReleaseIntegrityError("judge verdict task_id mismatch")
    if verdict["candidate_hash"] != digest or verdict.get("output_hash") != digest:
        raise ReleaseIntegrityError("judge verdict hash does not match the output digest")
    if verdict["policy_hash"] != proof.policy_hash:
        raise ReleaseIntegrityError("judge verdict policy hash mismatch")
    if str(verdict["action"]).upper() != "PASS":
        raise DualGateDenied("judge verdict is not PASS")

    event: dict[str, Any] = {
        "who": "DualGatePath",
        "what": "OUTENV_RELEASE_AUTHORIZED",
        "when": datetime.now(timezone.utc).isoformat(),
        "where": "Sovereignty-AI-Studio_v1.0.1",
        "why": "Gate proof, exact Heavy Judge verdict, and output digest verified",
        "how": "Gate proof -> independent judge binding -> SHA3-512 -> signed SCAR append",
        "authorization": proof.proof_id,
        "memory_loaded": bool(memory_loaded),
        "network_accessed": bool(network_accessed),
        "files_changed": [],
        "result": "PASS",
        "task_id": expected_task_id,
        "policy_hash": proof.policy_hash,
        "output_hash": digest,
        "judge_id": verdict["judge_id"],
    }
    event["event_hash"] = _release_event_hash(event)
    try:
        ack = evidence_sink(event)
    except Exception as exc:
        raise ReleaseIntegrityError("mandatory release evidence append failed") from exc
    _require_verifiable_evidence(event, ack)
    return DualGateReceipt(
        task_id=expected_task_id,
        authorization_proof_id=proof.proof_id,
        authorization_policy_hash=proof.policy_hash,
        output_hash=digest,
        output=output,
        release_status="PASS",
        evidence_event_hash=event["event_hash"],
    )


def run_dual_gated(
    *,
    proof: str,
    verification_key: bytes,
    task_id: str,
    owner_id: str,
    required_scope: tuple[str, ...],
    route_and_judge: Callable[[GateAuthorizationProof], Mapping[str, Any]],
    evidence_sink: Callable[[dict[str, Any]], Any],
    now: int | None = None,
    memory_loaded: bool = False,
    network_accessed: bool = False,
) -> DualGateReceipt:
    """Execute only after Gate 1; release only after verified evidence append."""
    claims = authorize_before_route(
        proof, verification_key=verification_key, task_id=task_id,
        owner_id=owner_id, required_scope=required_scope, now=now,
    )
    result = route_and_judge(claims)
    return verify_before_release(
        claims, result, expected_task_id=task_id, evidence_sink=evidence_sink,
        memory_loaded=memory_loaded, network_accessed=network_accessed,
    )


__all__ = ["DualGateDenied", "DualGateReceipt", "ReleaseIntegrityError", "authorize_before_route", "run_dual_gated", "verify_before_release"]
