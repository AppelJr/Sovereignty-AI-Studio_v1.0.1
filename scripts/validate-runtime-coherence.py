#!/usr/bin/env python3
"""Validate canonical service entrypoints, runtime version contract, ports and local-only boundaries."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config" / "runtime-coherence.json"
PORTS = {
    "python_bridge": 9897, "dashboard": 9898, "unified_server": 9899,
    "keycloak_http": 8080, "keycloak_https": 8443,
    "redis_internal": 6379, "postgres_internal": 5432,
}


def fail(message: str) -> None:
    raise SystemExit(f"runtime coherence failed: {message}")


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    canonical = manifest["canonical_runtime"]
    required = {"dashboard", "dashboard_server", "launcher", "python_bridge",
                "unified_server", "local_ci", "transport", "devassist_handler"}
    if not required.issubset(canonical):
        fail("canonical runtime manifest is missing required entrypoints")
    for name, relative_path in canonical.items():
        if not (ROOT / relative_path).exists():
            fail(f"canonical {name} is missing: {relative_path}")
    for alias, target in manifest["aliases"].items():
        if not (ROOT / target).exists():
            fail(f"compatibility alias target is missing: {alias} -> {target}")

    policy = manifest["state_policy"]
    if policy["default_mode"] != "local" or not policy["private_state_is_not_committed"]:
        fail("local-first/private-state policy violated")
    if not policy["provider_selection_is_owner_policy"] or not policy["implicit_fallback_is_disabled"]:
        fail("provider selection must remain owner-controlled with implicit fallback disabled")

    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    node_requirement = package.get("engines", {}).get("node", "")
    if not re.fullmatch(r">=\\s*24(?:\\.0(?:\\.0)?)?", node_requirement):
        fail(f"root package must declare Node.js >=24; got {node_requirement!r}")

    installer = (ROOT / "INSTALL.sh").read_text(encoding="utf-8")
    if "(( NODE_MAJOR >= 24 ))" not in installer or 'npm --version' not in installer:
        fail("installer must enforce Node.js 24+ and verify npm execution before installing")

    launcher = (ROOT / canonical["launcher"]).read_text(encoding="utf-8")
    required_tokens = (
        "${SG_PORT:-9897}", "${PORT:-${STATIC_PORT:-9898}}",
        "${PORT_UNIFIED:-${NODE_BRIDGE_PORT:-9899}}",
        '"$ROOT_DIR/python3_bridge.py"', '"$ROOT_DIR/server_9898.js"',
        '"$ROOT_DIR/Unified_Server.js"', "127.0.0.1",
    )
    for token in required_tokens:
        if token not in launcher:
            fail(f"canonical launcher missing required contract: {token}")
    if "(( NODE_MAJOR >= 24 ))" not in launcher:
        fail("canonical launcher must refuse Node.js versions below 24")

    if manifest["ports"] != PORTS:
        fail(f"port manifest mismatch: expected {PORTS}, got {manifest['ports']}")
    if len({PORTS["python_bridge"], PORTS["dashboard"], PORTS["unified_server"]}) != 3:
        fail("application service ports must be unique")

    dashboard_server = (ROOT / canonical["dashboard_server"]).read_text(encoding="utf-8")
    unified_server = (ROOT / canonical["unified_server"]).read_text(encoding="utf-8")
    if "127.0.0.1" not in dashboard_server or "9898" not in dashboard_server:
        fail("dashboard server must default to loopback port 9898")
    if "/ws/ui" not in dashboard_server or "READ_ONLY_UI_CHANNEL" not in dashboard_server:
        fail("dashboard UI WebSocket must remain read-only")
    if "upstreamPort" not in dashboard_server or "hostname: '127.0.0.1'" not in dashboard_server:
        fail("dashboard API proxy must use a fixed loopback upstream")
    if "9899" not in unified_server or "node-bridge/server" not in unified_server:
        fail("Unified Server must own port 9899 and reuse the Node bridge implementation")

    dashboard = (ROOT / canonical["dashboard"]).read_text(encoding="utf-8", errors="ignore")
    if "trimmed for brevity" in dashboard.lower():
        fail("canonical dashboard contains a truncated placeholder")
    print("runtime coherence passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
