from __future__ import annotations

import pytest

from backend.coordination.authorization_proof import issue_gate_authorization_proof, verify_gate_authorization_proof
from backend.policy.provider_lane_policy import (
    ProviderLane, ProviderLaneDenied, ProviderLaneRegistry, authorize_provider_dispatch,
)

KEY = b"provider-lane-policy-test-key"


def claims(scope):
    token = issue_gate_authorization_proof(
        proof_id="provider-policy-test", owner_id="owner", task_id="task",
        scope=scope, decision="OWNER_AUTHORIZED", policy_hash="policy",
        issued_at=100, expires_at=4_000_000_000, secret=KEY,
    )
    return verify_gate_authorization_proof(token, secret=KEY, expected_task_id="task")


def lane(provider_id="xai", enabled=True):
    return ProviderLane(
        provider_id=provider_id, enabled=enabled, connector_type="api",
        credential_ref=f"secret://{provider_id}", model_id="fixture-model",
        allowed_data_classes=("PUBLIC",), allowed_operations=("GENERATE",),
        allowed_resources=("public:completion",), jurisdiction="US",
        retention_policy="provider-contract",
    )


def test_exact_provider_and_operation_scope_allows_dispatch():
    authorize_provider_dispatch(
        claims(("provider:xai", "operation:generate")),
        provider_id="xai",
    )


def test_provider_scope_does_not_transfer_to_another_lane():
    with pytest.raises(ProviderLaneDenied):
        authorize_provider_dispatch(
            claims(("provider:xai", "operation:generate")),
            provider_id="anthropic",
        )


def test_missing_operation_scope_denies():
    with pytest.raises(ProviderLaneDenied):
        authorize_provider_dispatch(
            claims(("provider:xai",)), provider_id="xai",
        )


def test_wildcard_provider_scope_is_not_authority():
    with pytest.raises(ProviderLaneDenied):
        authorize_provider_dispatch(
            claims(("provider:*", "operation:generate")), provider_id="xai",
        )


def test_registry_rejects_duplicate_provider_identity():
    with pytest.raises(ValueError, match="duplicate"):
        ProviderLaneRegistry((lane(), lane("XAI")))


def test_registry_rejects_disabled_provider():
    registry = ProviderLaneRegistry((lane(enabled=False),))
    with pytest.raises(ProviderLaneDenied, match="disabled"):
        registry.get("xai")


def test_registry_rejects_unknown_provider():
    registry = ProviderLaneRegistry((lane(),))
    with pytest.raises(ProviderLaneDenied, match="unknown"):
        registry.get("duckai")


def test_lane_rejects_empty_data_class_or_operation():
    with pytest.raises(ValueError):
        ProviderLane(
            provider_id="bad", enabled=True, connector_type="api",
            credential_ref="secret://bad", model_id="model",
            allowed_data_classes=(), allowed_operations=(),
            allowed_resources=(), jurisdiction="US", retention_policy="none",
        )
