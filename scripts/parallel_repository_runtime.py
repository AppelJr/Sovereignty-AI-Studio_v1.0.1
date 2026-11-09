#!/usr/bin/env python3
"""Offline discovery and dependency planner for the 12-repository Sovereignty runtime.

This command does not execute repository code, start services, install dependencies,
contact remotes, or mutate checkouts. Runtime adapters remain separately gated.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "integration" / "parallel-repository-registry.json"


def load_manifest() -> dict[str, Any]:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if data.get("contract") != "SOVEREIGNTY_PARALLEL_REPOSITORY_RUNTIME/1.0":
        raise ValueError("unsupported parallel repository contract")
    repos = data.get("repositories")
    if not isinstance(repos, list) or not repos:
        raise ValueError("repositories must be a non-empty array")
    ids = [r.get("id") for r in repos]
    if len(ids) != len(set(ids)) or any(not isinstance(x, str) or not x for x in ids):
        raise ValueError("repository IDs must be unique non-empty strings")
    known = set(ids)
    for repo in repos:
        rel = Path(repo.get("local_path", ""))
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError(f"unsafe local_path for {repo.get('id')}")
        if not isinstance(repo.get("repository"), str) or "/" not in repo["repository"]:
            raise ValueError(f"invalid repository identity for {repo.get('id')}")
        for dep in repo.get("depends_on", []):
            if dep not in known:
                raise ValueError(f"unknown dependency {dep!r} for {repo['id']}")
    dependency_layers(repos)  # cycle check
    return data


def dependency_layers(repositories: list[dict[str, Any]]) -> list[list[str]]:
    pending = {r["id"]: set(r.get("depends_on", [])) for r in repositories}
    known = set(pending)
    for repo_id, dependencies in pending.items():
        unknown = dependencies - known
        if unknown:
            raise ValueError(f"unknown dependency {sorted(unknown)[0]!r} for {repo_id}")
    layers: list[list[str]] = []
    completed: set[str] = set()
    while pending:
        ready = sorted(k for k, deps in pending.items() if deps <= completed)
        if not ready:
            raise ValueError("dependency cycle detected")
        layers.append(ready)
        completed.update(ready)
        for key in ready:
            del pending[key]
    return layers


def repo_path(repo: dict[str, Any]) -> Path:
    if repo["id"] == "studio":
        configured = os.environ.get("SOVEREIGNTY_STUDIO_ROOT")
        return Path(configured).expanduser().resolve() if configured else ROOT
    workspace = Path(os.environ.get("SOVEREIGNTY_WORKSPACE", "~/Sovereignty")).expanduser().resolve()
    candidate = (workspace / repo["local_path"]).resolve()
    if candidate != workspace and workspace not in candidate.parents:
        raise ValueError(f"path escapes workspace for {repo['id']}")
    return candidate


async def git_output(path: Path, *args: str) -> str | None:
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", str(path), *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        if proc.returncode != 0:
            return None
        return stdout.decode("utf-8", errors="replace").strip()
    except (OSError, asyncio.TimeoutError):
        return None


def normalize_remote(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if value.startswith("git@github.com:"):
        value = "https://github.com/" + value.split(":", 1)[1]
    value = value.removesuffix(".git").rstrip("/").lower()
    return value


async def inspect_repository(repo: dict[str, Any]) -> dict[str, Any]:
    try:
        path = repo_path(repo)
    except ValueError as exc:
        return {"id": repo["id"], "checkout_status": "UNSAFE_PATH", "detail": str(exc)}
    if not path.is_dir():
        checkout = "MISSING"
        remote = head = None
    else:
        git_root, remote, head = await asyncio.gather(
            git_output(path, "rev-parse", "--show-toplevel"),
            git_output(path, "remote", "get-url", "origin"),
            git_output(path, "rev-parse", "--short", "HEAD"),
        )
        checkout = "NOT_A_GIT_REPOSITORY" if not git_root else "READY"
    expected = normalize_remote("https://github.com/" + repo["repository"] + ".git")
    actual = normalize_remote(remote)
    if checkout == "READY" and actual != expected:
        checkout = "REMOTE_MISMATCH"
    return {
        "id": repo["id"],
        "repository": repo["repository"],
        "path": str(path),
        "checkout_status": checkout,
        "runtime_status": "BLOCKED_ADAPTER_UNBOUND" if repo.get("adapter_status") == "UNBOUND" else "HOST_ONLY",
        "adapter_status": repo.get("adapter_status"),
        "origin_matches": actual == expected if actual else False,
        "head": head,
        "required_at_startup": bool(repo.get("required_at_startup")),
        "execution_type": repo.get("execution_type"),
        "parallel_group": repo.get("parallel_group"),
    }


async def run(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    repos = manifest["repositories"]
    layers = dependency_layers(repos)
    results = await asyncio.gather(*(inspect_repository(r) for r in repos))
    by_id = {r["id"]: r for r in results}
    required_bad = [
        r["id"] for r in results
        if r.get("required_at_startup") and r.get("checkout_status") != "READY"
    ]
    optional_bad = [
        r["id"] for r in results
        if not r.get("required_at_startup") and r.get("checkout_status") != "READY"
    ]
    adapter_unbound = [
        r["id"] for r in results if r.get("runtime_status") == "BLOCKED_ADAPTER_UNBOUND"
    ]
    report = {
        "contract": manifest["contract"],
        "mode": manifest["runtime_mode"],
        "network_used": False,
        "execution_started": False,
        "dependency_layers": layers,
        "repositories": results,
        "required_checkout_failures": required_bad,
        "optional_checkout_issues": optional_bad,
        "unbound_adapters": adapter_unbound,
        "checkout_preflight": "FAIL" if required_bad else "PASS",
        "runtime_readiness": "BLOCKED" if adapter_unbound or required_bad else "READY",
    }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("SOVEREIGNTY PARALLEL REPOSITORY PREFLIGHT")
        print(f"network_used: false | execution_started: false | mode: {manifest['runtime_mode']}")
        print("dependency layers (peers may run concurrently only after gate approval):")
        for index, layer in enumerate(layers):
            print(f"  L{index}: " + " | ".join(layer))
        print("\nrepository status:")
        for item in results:
            print(
                f"  {item['checkout_status']:20} {item['id']:28} "
                f"runtime={item.get('runtime_status', 'BLOCKED')}"
            )
        print(f"\ncheckout_preflight: {report['checkout_preflight']}")
        print(f"runtime_readiness: {report['runtime_readiness']}")
        print(f"unbound_adapters: {len(adapter_unbound)}")
        print("No repository code was executed.")
    if required_bad or (args.require_all and optional_bad):
        return 1
    if adapter_unbound:
        return 2
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable report")
    parser.add_argument("--require-all", action="store_true", help="fail if any optional checkout is missing")
    args = parser.parse_args()
    try:
        return asyncio.run(run(args))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"preflight: BLOCKED: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
