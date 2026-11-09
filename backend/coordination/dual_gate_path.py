"""Two-gate enforcement: authorization before routing, integrity before release."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
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
class EvidenceAppendReceipt:
    """Acknowledgment returned only after the evidence sink accepts an event."""

    event_type: str
    task_id: str
    event_id: str
    event_hash: str
    sequence: int


@dataclass(frozen=True, slots=True)
class DualGateReceipt:
    task_id: str
    authorization_proof_id: str
    authorization_policy_hash: str
    output_hash: str
    output: str
    release_status: str
    evidence_receipt: EvidenceAppendReceipt


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
    memory_loaded: bool = False,
    network_accessed: bool = False,
) -> DualGateReceipt:
    """Gate 2. Bind exact Judge verdict, output digest, and acknowledged evidence."""
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
    if not isinstance(verdict, Mapping):
        raise ReleaseIntegrityError("exact Heavy Judge verdict is required")
    if str(verdict.get("action", "")).upper() != "PASS":
        raise DualGateDenied("Heavy Judge verdict is not PASS")
    if verdict.get("task_id") != expected_task_id:
        raise ReleaseIntegrityError("Judge verdict task_id mismatch")
    if verdict.get("policy_hash") != proof.policy_hash:
        raise ReleaseIntegrityError("Judge verdict policy_hash mismatch")
    if verdict.get("candidate_hash") != digest or verdict.get("output_hash") != digest:
        raise ReleaseIntegrityError("Judge verdict candidate hash mismatch")
    judge_id = verdict.get("judge_id")
    judge_provider_id = verdict.get("judge_provider_id")
    source_provider_id = execution_result.get("source_provider_id")
    contributors = verdict.get("contributing_provider_ids")
    if not all(isinstance(value, str) and value.strip()
               for value in (judge_id, judge_provider_id, source_provider_id)):
        raise ReleaseIntegrityError("Judge and source-provider identities are required")
    if not isinstance(contributors, (list, tuple)) or not contributors:
        raise ReleaseIntegrityError("Council contributor identities are required")
    if any(not isinstance(value, str) or not value.strip() for value in contributors):
        raise ReleaseIntegrityError("Council contributor identity is malformed")
    contributor_ids = {value.strip().casefold() for value in contributors}
    if source_provider_id.strip().casefold() not in contributor_ids and source_provider_id != "council:aggregate":
        raise ReleaseIntegrityError("candidate source is not bound to Council contributors")
    if judge_provider_id.strip().casefold() in contributor_ids:
        raise ReleaseIntegrityError("provider cannot judge its own or a contributing lane's output")
    if not callable(evidence_sink):
        raise ReleaseIntegrityError("mandatory release evidence sink is unavailable")

    event = {
        "who": "DualGatePath",
        "what": "OUTENV_RELEASE_AUTHORIZED",
        "when": datetime.now(timezone.utc).isoformat(),
        "where": "Sovereignty-AI-Studio_v1.0.1",
        "why": "Gate proof, independent Judge verdict, and exact candidate digest verified",
        "how": "pre-route Gate proof + Council-mediated independent Judge + SHA3-512 + acknowledged SCAR append",
        "authorization": proof.proof_id,
        "memory_loaded": bool(memory_loaded),
        "network_accessed": bool(network_accessed),
        "files_changed": [],
        "result": "PASS",
        "task_id": expected_task_id,
        "policy_hash": proof.policy_hash,
        "output_hash": digest,
        "candidate_hash": digest,
        "judge_id": judge_id,
        "judge_provider_id": judge_provider_id,
        "source_provider_id": source_provider_id,
        "contributing_provider_ids": list(contributors),
    }
    try:
        append_receipt = evidence_sink(event)
    except Exception as exc:
        raise ReleaseIntegrityError("mandatory release evidence append failed") from exc
    if not isinstance(append_receipt, EvidenceAppendReceipt):
        raise ReleaseIntegrityError("release evidence sink returned no verifiable append receipt")
    if (
        append_receipt.event_type != event["what"]
        or append_receipt.task_id != expected_task_id
        or not append_receipt.event_id
        or not append_receipt.event_hash
        or not isinstance(append_receipt.sequence, int)
        or append_receipt.sequence < 0
    ):
        raise ReleaseIntegrityError("release evidence append receipt binding mismatch")

    return DualGateReceipt(
        task_id=expected_task_id,
        authorization_proof_id=proof.proof_id,
        authorization_policy_hash=proof.policy_hash,
        output_hash=digest,
        output=output,
        release_status="PASS",
        evidence_receipt=append_receipt,
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
    """Execute only after Gate 1; release only after Gate 2 and durable evidence."""
    claims = authorize_before_route(
        proof, verification_key=verification_key, task_id=task_id,
        owner_id=owner_id, required_scope=required_scope, now=now,
    )
    result = route_and_judge(claims)
    return verify_before_release(
        claims, result, expected_task_id=task_id, evidence_sink=evidence_sink,
        memory_loaded=memory_loaded, network_accessed=network_accessed,
    )
