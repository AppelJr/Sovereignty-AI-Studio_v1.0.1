#!/usr/bin/env python3
"""Validate the static Sovereignty cross-repository integration manifest.

This checks declarations and local runtime coherence only. It does not prove
remote repository existence, adapter execution, cryptographic trust, or release
readiness. Those require live conformance evidence.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

EXPECTED_COUNT = 18
EXPECTED_OWNER = "AppelJr"
EXPECTED_PORTS = {
    "python_bridge": 9897,
    "dashboard": 9898,
    "unified_server": 9899,
}


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load {path}: {exc}") from exc
    if type(value) is not dict:
        raise ValueError(f"{path} must contain a JSON object")
    return value


def validate(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    registry_path = root / "integration" / "repository-registry.json"
    runtime_path = root / "config" / "runtime-coherence.json"

    try:
        registry = load_json(registry_path)
        runtime = load_json(runtime_path)
    except ValueError as exc:
        return {
            "status": "FAIL",
            "scope": "static-manifest-validation-only",
            "errors": [str(exc)],
            "warnings": [],
            "repository_count": 0,
            "declared_only_count": 0,
            "runtime_ports": {},
        }

    repositories = registry.get("repositories")
    if type(repositories) is not list:
        errors.append("repositories must be an ordered JSON array")
        repositories = []

    names: list[str] = []
    roles: list[str] = []
    declared_only = 0
    for index, item in enumerate(repositories):
        if type(item) is not dict:
            errors.append(f"repositories[{index}] must be an object")
            continue
        name = item.get("repository")
        role = item.get("role")
        if type(name) is not str or not name.startswith(EXPECTED_OWNER + "/"):
            errors.append(f"repositories[{index}] must use canonical {EXPECTED_OWNER}/owner")
        else:
            names.append(name)
        if type(role) is not str or not role.strip():
            errors.append(f"repositories[{index}] has no role")
        else:
            roles.append(role)
        if item.get("integration_status") == "DECLARED" or item.get("test_status") == "NOT_RUN":
            declared_only += 1

    if len(repositories) != EXPECTED_COUNT:
        errors.append(f"expected exactly {EXPECTED_COUNT} repository entries; found {len(repositories)}")
    if len(names) != len(set(names)):
        errors.append("duplicate repository names detected")
    if len(roles) != len(set(roles)):
        warnings.append("multiple repositories share a role; verify intentional role multiplicity")
    if registry.get("canonical_runtime") != "AppelJr/Sovereignty-AI-Studio_v1.0.1":
        errors.append("canonical_runtime does not identify the AppelJr Studio repository")

    ports = runtime.get("ports")
    if type(ports) is not dict:
        errors.append("runtime ports object missing")
        ports = {}
    for name, expected in EXPECTED_PORTS.items():
        if ports.get(name) != expected:
            errors.append(f"runtime port {name} must be {expected}")
    app_ports = [ports.get(name) for name in EXPECTED_PORTS]
    if len([p for p in app_ports if type(p) is int]) != 3 or len(set(app_ports)) != 3:
        errors.append("application ports must be three distinct integers")

    state_policy = runtime.get("state_policy")
    if type(state_policy) is not dict:
        errors.append("runtime state_policy object missing")
    else:
        if state_policy.get("default_mode") != "local":
            errors.append("default runtime mode must remain local")
        if state_policy.get("implicit_fallback_disabled") is not True:
            errors.append("implicit fallback must remain disabled")
        if state_policy.get("private_state_is_not_committed") is not True:
            errors.append("private state must remain excluded from commits")

    if registry.get("status") != "validated":
        warnings.append("registry is declarative, not validated against live repository and adapter evidence")
    if declared_only:
        warnings.append(f"{declared_only} entries remain declared and/or untested")
    warnings.append("this validator does not test Gate signatures, provider transports, SCAR durability, MCP enforcement, or deployment")

    return {
        "status": "PASS" if not errors else "FAIL",
        "scope": "static-manifest-validation-only",
        "repository_count": len(repositories),
        "unique_repository_count": len(set(names)),
        "declared_only_count": declared_only,
        "runtime_ports": {key: ports.get(key) for key in EXPECTED_PORTS},
        "errors": errors,
        "warnings": warnings,
        "release_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    report = validate(args.root.resolve())
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        print(f"STATIC_MANIFEST={report['status']}")
        print(f"REPOSITORIES={report['repository_count']}/{EXPECTED_COUNT}")
        print(f"DECLARED_OR_UNTESTED={report['declared_only_count']}")
        print("RELEASE_READY=NO")
        for error in report["errors"]:
            print(f"FAIL: {error}")
        for warning in report["warnings"]:
            print(f"UNPROVEN: {warning}")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
