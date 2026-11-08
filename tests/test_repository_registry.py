from __future__ import annotations

import json
from pathlib import Path


def test_registry_contains_exactly_eighteen_unique_repositories():
    root = Path(__file__).resolve().parents[1]
    registry = json.loads((root / "integration" / "repository-registry.json").read_text())
    repositories = registry["repositories"]
    names = [item["repository"] for item in repositories]
    assert len(repositories) == 18
    assert len(set(names)) == 18
    assert registry["canonical_runtime"] == "AppelJr/Sovereignty-AI-Studio_v1.0.1"


def test_every_registry_entry_has_role_and_honest_validation_state():
    root = Path(__file__).resolve().parents[1]
    registry = json.loads((root / "integration" / "repository-registry.json").read_text())
    for item in registry["repositories"]:
        assert item["role"]
        assert item["integration_status"]
        assert item["test_status"] == "NOT_RUN"
