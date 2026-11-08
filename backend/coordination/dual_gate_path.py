"""Two-gate enforcement: authorization before routing, integrity before release."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
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


def authorize_before_route(
    proof: str,
    *,
    verification_key: bytes,
    task_id: str,
    owner_id: str,
    required_scope: tuple[str, ...],
    now: int | None = None,
) -> GateAuthorizationProof:
    """Gate 1. Verify cryptographic proof and bind it to owner/task/scope."""
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
    if not claims.allows_decision("ALLOW", "APPROVED", "OWNER_AUTHORIZED",
                                  "DELEGATED_AUTHORIZED", "OWNER_OVERRIDE"):
        raise DualGateDenied("pre-route Gate decision is not an allow")
    return claims


def verify_before_release(
    proof: GateAuthorizationProof,
    execution_result: Mapping[str, Any],
    *,
    expected_task_id: str,
    evidence_sink: Callable[[dict[str, Any]], Any],
) -> DualGateReceipt:
    """Gate 2. Validate PASS, payload digest, and append evidence before release."""
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
    receipt = DualGateReceipt(
        task_id=expected_task_id,
        authorization_proof_id=proof.proof_id,
        authorization_policy_hash=proof.policy_hash,
        output_hash=digest,
        output=output,
        release_status="PASS",
    )
    event = {
        "who": "DualGatePath",
        "what": "OUTENV_RELEASE_AUTHORIZED",
        "when": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        "where": "Sovereignty-AI-Studio_v1.0.1",
        "why": "Gate proof and Heavy Judge output integrity verified",
        "how": "pre-route Gate proof + post-judge SHA3-512 verification",
        "authorization": proof.proof_id,
        "memory_loaded": False,
        "network_accessed": False,
        "files_changed": [],
        "result": "PASS",
        "task_id": expected_task_id,
        "policy_hash": proof.policy_hash,
        "output_hash": digest,
    }
    try:
        evidence_sink(event)
    except Exception as exc:
        raise ReleaseIntegrityError("mandatory release evidence append failed") from exc
    return receipt


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
) -> DualGateReceipt:
    """Execute only after Gate 1; release only after Gate 2 and durable evidence."""
    claims = authorize_before_route(
        proof, verification_key=verification_key, task_id=task_id,
        owner_id=owner_id, required_scope=required_scope, now=now,
    )
    result = route_and_judge(claims)
    return verify_before_release(
        claims, result, expected_task_id=task_id, evidence_sink=evidence_sink
    )
