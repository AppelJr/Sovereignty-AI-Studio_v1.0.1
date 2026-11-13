"""Provider-specific authorization primitives for the federated provider boundary.

Provider identity is configuration, never authority. A verified Gate proof must
contain exact provider and operation scopes before a connector can be called.
Unknown, wildcard, or missing scopes fail closed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from backend.coordination.authorization_proof import GateAuthorizationProof


class ProviderLaneDenied(PermissionError):
    """A provider lane is disabled, unknown, or outside the Gate proof scope."""


@dataclass(frozen=True, slots=True)
class ProviderLane:
    provider_id: str
    enabled: bool
    connector_type: str
    credential_ref: str
    model_id: str
    allowed_data_classes: tuple[str, ...]
    allowed_operations: tuple[str, ...]
    allowed_resources: tuple[str, ...]
    jurisdiction: str
    retention_policy: str

    def __post_init__(self) -> None:
        required = (
            self.provider_id, self.connector_type, self.credential_ref,
            self.model_id, self.jurisdiction, self.retention_policy,
        )
        if any(not isinstance(value, str) or not value.strip() for value in required):
            raise ValueError("provider lane identity and security fields must be explicit")
        if not isinstance(self.enabled, bool):
            raise ValueError("provider enabled must be boolean")
        for name, values in (
            ("allowed_data_classes", self.allowed_data_classes),
            ("allowed_operations", self.allowed_operations),
            ("allowed_resources", self.allowed_resources),
        ):
            if not isinstance(values, tuple) or any(
                not isinstance(value, str) or not value.strip() for value in values
            ):
                raise ValueError(f"{name} must be an explicit tuple of non-empty strings")
        if not self.allowed_data_classes or not self.allowed_operations:
            raise ValueError("data classes and operations must be explicitly restricted")


class ProviderLaneRegistry:
    """Immutable-by-copy registry; duplicate IDs and unknown lookups are rejected."""

    def __init__(self, lanes: Iterable[ProviderLane]) -> None:
        indexed: dict[str, ProviderLane] = {}
        for lane in lanes:
            if not isinstance(lane, ProviderLane):
                raise TypeError("registry accepts ProviderLane objects only")
            key = lane.provider_id.casefold()
            if key in indexed:
                raise ValueError("duplicate provider_id")
            indexed[key] = lane
        self._lanes = indexed

    def get(self, provider_id: str) -> ProviderLane:
        if not isinstance(provider_id, str) or not provider_id.strip():
            raise ProviderLaneDenied("provider identity is required")
        lane = self._lanes.get(provider_id.casefold())
        if lane is None:
            raise ProviderLaneDenied("unknown provider lane")
        if not lane.enabled:
            raise ProviderLaneDenied("provider lane is disabled")
        return lane

    def provider_ids(self) -> tuple[str, ...]:
        return tuple(lane.provider_id for lane in self._lanes.values())


def authorize_provider_dispatch(
    claims: GateAuthorizationProof,
    *,
    provider_id: str,
    operation: str = "generate",
) -> None:
    """Require exact, independent provider + operation claims on a verified proof."""
    if not isinstance(claims, GateAuthorizationProof):
        raise ProviderLaneDenied("verified Gate claims are required")
    if not isinstance(provider_id, str) or not provider_id.strip():
        raise ProviderLaneDenied("provider identity is required")
    if not isinstance(operation, str) or not operation.strip():
        raise ProviderLaneDenied("operation is required")
    required = {f"provider:{provider_id.casefold()}", f"operation:{operation.casefold()}"}
    granted = {item.casefold() for item in claims.scope}
    if not required.issubset(granted):
        raise ProviderLaneDenied("Gate proof does not authorize this provider and operation")
