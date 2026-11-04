from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_manifest_has_one_canonical_entrypoint() -> None:
    manifest = json.loads((ROOT / "config" / "runtime-coherence.json").read_text())
    canonical = manifest["canonical_runtime"]
    assert canonical["dashboard"] == "DevAssist420SGHv119.html"
    assert canonical["dashboard_server"] == "server_9898.js"
    assert canonical["python_bridge"] == "python3_bridge.py"
    assert canonical["unified_server"] == "Unified_Server.js"
    assert canonical["launcher"] == "START_SERVER.sh"
    assert canonical["local_ci"] == "scripts/local-ci.sh"
    for key in ("dashboard", "dashboard_server", "python_bridge", "unified_server", "launcher"):
        assert (ROOT / canonical[key]).is_file()


def test_runtime_manifest_ports_are_symmetric() -> None:
    manifest = json.loads((ROOT / "config" / "runtime-coherence.json").read_text())
    assert manifest["ports"] == {
        "python_bridge": 9897,
        "dashboard": 9898,
        "unified_server": 9899,
        "keycloak_http": 8080,
        "keycloak_https": 8443,
        "redis_internal": 6379,
        "postgres_internal": 5432,
    }


def test_aliases_do_not_become_new_runtime_owners() -> None:
    manifest = json.loads((ROOT / "config" / "runtime-coherence.json").read_text())
    assert manifest["aliases"]["start-all.sh"] == "START_SERVER.sh"
    assert manifest["aliases"]["server.js"] == "Unified_Server.js"
    assert manifest["aliases"]["sovereignty_full_server.py"] == "python3_bridge.py"


def test_private_state_and_provider_choice_are_policy_bound() -> None:
    manifest = json.loads((ROOT / "config" / "runtime-coherence.json").read_text())
    policy = manifest["state_policy"]
    assert policy["private_state_is_not_committed"] is True
    assert policy["provider_selection_is_owner_policy"] is True
    assert policy["implicit_fallback_is_disabled"] is True
