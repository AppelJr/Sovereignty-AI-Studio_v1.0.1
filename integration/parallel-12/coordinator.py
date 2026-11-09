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
    seen_repositories: list[str] = []
    dependencies = {}
    for stage in registry["stages"]:
        stage_repositories = stage.get("repositories", [])
        if not set(stage_repositories) <= set(ids):
            raise ValueError(f"unknown repository in stage {stage['id']}")
        seen_repositories.extend(stage_repositories)
        stage_dependencies = set(stage.get("depends_on", []))
        if not stage_dependencies <= stage_ids:
            raise ValueError(f"unknown stage dependency in {stage['id']}")
        dependencies[stage["id"]] = stage_dependencies
    if len(seen_repositories) != len(set(seen_repositories)) or set(seen_repositories) != set(ids):
        raise ValueError("every repository must appear exactly once across stages")
    completed: set[str] = set()
    pending = dict(dependencies)
    while pending:
        ready = {key for key, deps in pending.items() if deps <= completed}
        if not ready:
            raise ValueError("integration stage dependency cycle detected")
        completed.update(ready)
        for key in ready:
            del pending[key]
    return registry


def validate_preflight(evidence: Mapping[str, Any]) -> None:
    missing = [key for key in REQUIRED_PREFLIGHT if evidence.get(key) is not True]
    if missing:
        raise PermissionError("preflight blocked: " + ",".join(missing))


def _digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class Parallel12Coordinator:
    def __init__(
        self,
        adapters: Mapping[str, Callable[..., Awaitable[Mapping[str, Any]]]],
        authorization_verifier: Callable[[Any, str], bool],
    ) -> None:
        if not callable(authorization_verifier):
            raise TypeError("cryptographic authorization verifier is required")
        self.registry = load_registry()
        if not isinstance(adapters, Mapping):
            raise TypeError("adapters must be a mapping")
        known_ids = {item["id"] for item in self.registry["repositories"]}
        unknown = set(adapters) - known_ids
        if unknown:
            raise ValueError("unregistered adapter IDs: " + ",".join(sorted(unknown)))
        invalid = [
            adapter_id for adapter_id, adapter in adapters.items()
            if not isinstance(adapter_id, str) or not adapter_id
            or not callable(adapter) or not asyncio.iscoroutinefunction(adapter)
        ]
        if invalid:
            raise TypeError("adapters must be named async callables: " + ",".join(map(str, invalid)))
        self.adapters = dict(adapters)
        self.authorization_verifier = authorization_verifier
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
        if self.authorization_verifier(authorization, task_id) is not True:
            raise PermissionError("GateAuthorization cryptographic verification failed")
        stage = next((item for item in self.registry["stages"] if item["id"] == stage_id), None)
        if stage is None:
            raise ValueError("unknown integration stage")

        missing_dependencies = set(stage.get("depends_on", [])) - self.completed_stages
        if missing_dependencies:
            raise RuntimeError("stage dependencies incomplete: " + ",".join(sorted(missing_dependencies)))

        # Validate once, then give each concurrent adapter an isolated JSON value.
        # This prevents shared nested objects from becoming a cross-adapter write channel.
        try:
            canonical_payload = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), allow_nan=False
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("payload must contain finite JSON values only") from exc
        requested = list(stage["repositories"])
        missing = [repo_id for repo_id in requested if repo_id not in self.adapters]
        if missing:
            raise RuntimeError("adapters unbound: " + ",".join(missing))

        async def invoke(repo_id: str) -> AdapterResult:
            result = await self.adapters[repo_id](
                task_id=task_id,
                payload=json.loads(canonical_payload),
                authorization=authorization,
            )
            if not isinstance(result, Mapping) or result.get("status") != "pass":
                return AdapterResult(repo_id, "failed", reason_code="ADAPTER_DID_NOT_PASS")
            try:
                evidence_digest = _digest(result)
            except (TypeError, ValueError):
                return AdapterResult(repo_id, "failed", reason_code="ADAPTER_RESULT_NOT_CANONICAL_JSON")
            return AdapterResult(repo_id, "pass", evidence_digest)

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
