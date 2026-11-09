"""Stage-gated Parallel-12 coordinator.

Only explicitly registered adapters run. No shell, subprocess, dynamic import,
network transport, repository mutation, or implicit provider SDK is used here.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

REGISTRY_PATH = Path(__file__).with_name("registry.json")
REQUIRED_PREFLIGHT = (
    "owner_acceptance",
    "registry_valid",
    "branches_isolated",
    "authorization_boundary_reviewed",
    "no_merge_enabled",
)


@dataclass(frozen=True)
class AdapterResult:
    adapter_id: str
    status: str
    evidence_digest: str | None = None
    reason_code: str | None = None


def load_registry() -> dict[str, Any]:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    if registry.get("contract") != "SOVEREIGNTY_PARALLEL_12/1.0":
        raise ValueError("unsupported Parallel-12 contract")
    repositories = registry.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != 12:
        raise ValueError("registry must declare exactly twelve repositories")
    ids = [item.get("id") for item in repositories]
    if any(not isinstance(value, str) or not value for value in ids) or len(ids) != len(set(ids)):
        raise ValueError("repository IDs must be unique non-empty strings")
    stage_ids = {stage["id"] for stage in registry.get("stages", [])}
    if not stage_ids:
        raise ValueError("at least one stage is required")
    for stage in registry["stages"]:
        if not set(stage.get("repositories", [])) <= set(ids):
            raise ValueError(f"unknown repository in stage {stage['id']}")
        if not set(stage.get("depends_on", [])) <= stage_ids:
            raise ValueError(f"unknown stage dependency in {stage['id']}")
    return registry


def validate_preflight(evidence: Mapping[str, Any]) -> None:
    missing = [key for key in REQUIRED_PREFLIGHT if evidence.get(key) is not True]
    if missing:
        raise PermissionError("preflight blocked: " + ",".join(missing))


def _digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class Parallel12Coordinator:
    def __init__(self, adapters: Mapping[str, Callable[..., Awaitable[Mapping[str, Any]]]]) -> None:
        self.registry = load_registry()
        self.adapters = dict(adapters)
        self.completed_stages: set[str] = set()

    async def run_stage(
        self,
        *,
        stage_id: str,
        task_id: str,
        payload: Mapping[str, Any],
        authorization: Any,
        preflight_evidence: Mapping[str, Any],
    ) -> list[AdapterResult]:
        validate_preflight(preflight_evidence)
        if not callable(getattr(authorization, "is_valid_for", None)) or authorization.is_valid_for(task_id) is not True:
            raise PermissionError("valid task-bound GateAuthorization required")
        stage = next((item for item in self.registry["stages"] if item["id"] == stage_id), None)
        if stage is None:
            raise ValueError("unknown integration stage")

        missing_dependencies = set(stage.get("depends_on", [])) - self.completed_stages
        if missing_dependencies:
            raise RuntimeError("stage dependencies incomplete: " + ",".join(sorted(missing_dependencies)))

        requested = list(stage["repositories"])
        missing = [repo_id for repo_id in requested if repo_id not in self.adapters]
        if missing:
            raise RuntimeError("adapters unbound: " + ",".join(missing))

        async def invoke(repo_id: str) -> AdapterResult:
            result = await self.adapters[repo_id](
                task_id=task_id,
                payload=dict(payload),
                authorization=authorization,
            )
            if not isinstance(result, Mapping) or result.get("status") != "pass":
                return AdapterResult(repo_id, "failed", reason_code="ADAPTER_DID_NOT_PASS")
            return AdapterResult(repo_id, "pass", _digest(result))

        tasks = [asyncio.create_task(invoke(repo_id)) for repo_id in requested]
        try:
            results = list(await asyncio.gather(*tasks))
        except BaseException:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        if any(result.status != "pass" for result in results):
            return results
        self.completed_stages.add(stage_id)
        return results
