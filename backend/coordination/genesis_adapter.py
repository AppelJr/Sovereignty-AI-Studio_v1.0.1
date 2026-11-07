"""Genesis route adapter.

Genesis selects a route after a **verified Gate authorization proof**.
It never grants authority and never executes a tool.

Plain mappings such as ``{\"decision\": \"OWNER_AUTHORIZED\", \"policy_hash\": \"...\"}``
are rejected. Only a Gate-signed proof that binds task, owner, scope, policy,
and expiry is accepted.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .authorization_proof import (
    AuthorizationProofError,
    GateAuthorizationProof,
    verify_gate_authorization_proof,
)
from .execution_contracts import RouteDecision
from .task_envelope import TaskEnvelope


_APPROVED_DECISIONS = frozenset(
    {"ALLOW", "APPROVED", "OWNER_AUTHORIZED", "DELEGATED_AUTHORIZED", "OWNER_OVERRIDE"}
)


@dataclass(frozen=True, slots=True)
class GenesisRouterAdapter:
    """Choose an execution route from a Gate-verified authorization proof."""

    routes_by_mode: Mapping[str, str] | None = None
    proof_secret: bytes | None = None
    now: int | None = None

    def __post_init__(self) -> None:
        routes = self.routes_by_mode or {
            "offline": "devassist",
            "hybrid": "devassist",
            "online": "sovereignty-runtime",
        }
        object.__setattr__(self, "routes_by_mode", dict(routes))

    def decide(self, task: TaskEnvelope, authorization: object) -> RouteDecision:
        """Return a route only when a Gate proof verifies and matches the task."""
        try:
            verified = verify_gate_authorization_proof(
                authorization,
                secret=self.proof_secret,
                now=self.now,
                expected_task_id=task.task_id,
                required_scope=task.scope,
            )
        except AuthorizationProofError as exc:
            raise PermissionError(
                f"route selection requires a verified Gate authorization proof: {exc}"
            ) from exc

        if verified.decision not in _APPROVED_DECISIONS:
            raise PermissionError(
                f"route selection denied by Gate decision: {verified.decision}"
            )

        if verified.owner_id and task.owner and verified.owner_id != task.owner:
            raise PermissionError("gate proof owner_id does not match task owner")

        route = self.routes_by_mode.get(task.mode) if self.routes_by_mode else None
        if not route:
            raise ValueError(f"no execution route configured for mode: {task.mode}")

        return RouteDecision(
            task_id=task.task_id,
            decision="ALLOW",
            route=route,
            mode=task.mode,
            reason_code="ROUTE_AUTHORIZED",
            policy_hash=verified.policy_hash,
            requires_owner_approval=bool(
                verified.decision == "OWNER_OVERRIDE"
                or task.requires_owner_approval
            ),
        )

    def verify_only(
        self, task: TaskEnvelope, authorization: object
    ) -> GateAuthorizationProof:
        """Expose verified claims without selecting a route (inspection / SCAR)."""
        return verify_gate_authorization_proof(
            authorization,
            secret=self.proof_secret,
            now=self.now,
            expected_task_id=task.task_id,
            required_scope=task.scope,
        )
