import asyncio
import pytest

from coordinator import Parallel12Coordinator, load_registry, validate_preflight


class Authorization:
    def is_valid_for(self, task_id):
        return task_id == "task-1"


PREFLIGHT = {
    "owner_acceptance": True,
    "registry_valid": True,
    "branches_isolated": True,
    "authorization_boundary_reviewed": True,
    "no_merge_enabled": True,
}


def test_registry_contains_twelve_unique_repositories():
    registry = load_registry()
    assert len(registry["repositories"]) == 12
    assert len({item["id"] for item in registry["repositories"]}) == 12


def test_preflight_fails_closed():
    with pytest.raises(PermissionError):
        validate_preflight({"owner_acceptance": True})


def test_missing_adapter_blocks_stage_before_execution():
    coordinator = Parallel12Coordinator({}, authorization_verifier=lambda _auth, _task: True)
    with pytest.raises(RuntimeError, match="adapters unbound"):
        asyncio.run(coordinator.run_stage(
            stage_id="stage-1-control",
            task_id="task-1",
            payload={},
            authorization=Authorization(),
            preflight_evidence=PREFLIGHT,
        ))


def test_missing_authorization_blocks_before_adapter():
    called = []
    async def adapter(**kwargs):
        called.append(True)
        return {"status": "pass"}
    coordinator = Parallel12Coordinator({
        "genesis": adapter, "gateone": adapter,
        "sovereignty-gate": adapter, "risk-engine": adapter,
    }, authorization_verifier=lambda auth, task: auth.is_valid_for(task))
    with pytest.raises(PermissionError):
        asyncio.run(coordinator.run_stage(
            stage_id="stage-1-control",
            task_id="task-1",
            payload={},
            authorization=object(),
            preflight_evidence=PREFLIGHT,
        ))
    assert called == []


def test_parallel_stage_runs_all_registered_adapters():
    called = []
    async def adapter(**kwargs):
        called.append(kwargs["task_id"])
        return {"status": "pass", "result": "bounded"}
    coordinator = Parallel12Coordinator({
        "genesis": adapter, "gateone": adapter,
        "sovereignty-gate": adapter, "risk-engine": adapter,
    }, authorization_verifier=lambda auth, task: auth.is_valid_for(task))
    results = asyncio.run(coordinator.run_stage(
        stage_id="stage-1-control",
        task_id="task-1",
        payload={"intent": "inspect"},
        authorization=Authorization(),
        preflight_evidence=PREFLIGHT,
    ))
    assert len(results) == 4
    assert all(result.status == "pass" for result in results)
    assert called == ["task-1"] * 4


def test_later_stage_requires_prior_stage_pass():
    coordinator = Parallel12Coordinator({}, authorization_verifier=lambda _auth, _task: True)
    with pytest.raises(RuntimeError, match="dependencies incomplete"):
        asyncio.run(coordinator.run_stage(
            stage_id="stage-2-parallel-analysis",
            task_id="task-1",
            payload={},
            authorization=Authorization(),
            preflight_evidence=PREFLIGHT,
        ))


def test_registry_rejects_stage_dependency_cycle(monkeypatch, tmp_path):
    import json
    import coordinator as module
    registry = load_registry()
    registry["stages"][0]["depends_on"] = ["stage-5-studio-integration"]
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    monkeypatch.setattr(module, "REGISTRY_PATH", path)
    with pytest.raises(ValueError, match="cycle"):
        module.load_registry()


def test_cryptographic_verifier_failure_blocks_stage():
    called = []
    async def adapter(**kwargs):
        called.append(True)
        return {"status": "pass"}
    coordinator = Parallel12Coordinator({
        "genesis": adapter, "gateone": adapter,
        "sovereignty-gate": adapter, "risk-engine": adapter,
    }, authorization_verifier=lambda _auth, _task: False)
    with pytest.raises(PermissionError, match="cryptographic verification"):
        asyncio.run(coordinator.run_stage(
            stage_id="stage-1-control", task_id="task-1", payload={},
            authorization=Authorization(), preflight_evidence=PREFLIGHT,
        ))
    assert called == []


def test_constructor_rejects_unregistered_adapter():
    with pytest.raises(ValueError, match="unregistered adapter"):
        Parallel12Coordinator({"unexpected-repo": asyncio.sleep}, lambda _a, _t: True)


def test_constructor_rejects_sync_adapter():
    def sync_adapter(**_kwargs):
        return {"status": "pass"}
    with pytest.raises(TypeError, match="async callables"):
        Parallel12Coordinator({"genesis": sync_adapter}, lambda _a, _t: True)


def test_payload_rejects_non_finite_json_values():
    coordinator = Parallel12Coordinator({}, lambda _a, _t: True)
    with pytest.raises(ValueError, match="finite JSON"):
        asyncio.run(coordinator.run_stage(
            stage_id="stage-1-control", task_id="task-1",
            payload={"unsafe": float("nan")}, authorization=Authorization(),
            preflight_evidence=PREFLIGHT,
        ))


def test_each_adapter_receives_isolated_payload_copy():
    received = []
    async def adapter(**kwargs):
        payload = kwargs["payload"]
        received.append(payload)
        payload["nested"]["value"] = "mutated"
        return {"status": "pass"}
    coordinator = Parallel12Coordinator({
        "genesis": adapter, "gateone": adapter,
        "sovereignty-gate": adapter, "risk-engine": adapter,
    }, lambda auth, task: auth.is_valid_for(task))
    asyncio.run(coordinator.run_stage(
        stage_id="stage-1-control", task_id="task-1",
        payload={"nested": {"value": "original"}},
        authorization=Authorization(), preflight_evidence=PREFLIGHT,
    ))
    assert len(received) == 4
    assert all(item["nested"]["value"] == "mutated" for item in received)
    assert len({id(item) for item in received}) == 4
