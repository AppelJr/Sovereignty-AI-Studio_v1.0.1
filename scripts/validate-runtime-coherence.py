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
    "production_ingress_https": 9443, "development_http": 9880,
    "production_ingress_bind": "127.0.0.1",
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
    if not re.fullmatch(r">=\s*24(?:\.0(?:\.0)?)?", node_requirement):
        fail(f"root package must declare Node.js >=24; got {node_requirement!r}")

    installer = (ROOT / "INSTALL.sh").read_text(encoding="utf-8")
    if "(( NODE_MAJOR >= 24 ))" not in installer or 'npm --version' not in installer:
        fail("installer must enforce Node.js 24+ and verify npm execution before installing")
    if "cargo fetch" not in installer or "CARGO_TMP_DIR" not in installer:
        fail("installer must prefetch Diamond Core crates into the local Cargo cache without changing the checkout")

    launcher = (ROOT / canonical["launcher"]).read_text(encoding="utf-8")
    required_tokens = (
        "${SG_PORT:-9897}", "${PORT:-${STATIC_PORT:-9898}}",
        "${PORT_UNIFIED:-${NODE_BRIDGE_PORT:-9899}}",
        '"$ROOT_DIR/python3_bridge.py"', '"$ROOT_DIR/server_9898.js"',
        '"$ROOT_DIR/Unified_Server.js"', "127.0.0.1",
        "SOVEREIGN_STATE_ROOT", "Admin/On Device Memory Storage",
        "/api/devassist/status", "CONTROL_PLANE=ONLINE", "INFERENCE=",
        "CHECKPOINT_STATUS=", "CHECKPOINT_RESUME_ALLOWED=",
    )
    for token in required_tokens:
        if token not in launcher:
            fail(f"canonical launcher missing required contract: {token}")
    if "(( NODE_MAJOR >= 24 ))" not in launcher:
        fail("canonical launcher must refuse Node.js versions below 24")

    diamond_gate = (ROOT / "scripts" / "diamond-core-runtime-gate.sh").read_text(encoding="utf-8")
    if "CARGO_NET_OFFLINE=true" not in diamond_gate or 'mktemp -d' not in diamond_gate:
        fail("Diamond Core runtime gate must be offline and isolated from the working tree")
    if "--locked" in diamond_gate:
        fail("Diamond Core runtime gate must not require a missing repository Cargo.lock")

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

    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    for token in ('127.0.0.1:9443:443', '127.0.0.1:9880:80', '127.0.0.1:9899:9899'):
        if token not in compose:
            fail(f"Docker ingress must be loopback-bound: missing {token}")
    docker_workflow = (ROOT / ".github" / "workflows" / "docker-publish.yml").read_text(encoding="utf-8")
    if "packages: write" in docker_workflow or "docker push" in docker_workflow:
        fail("local-only Docker CI must not publish images or request package write permission")
    # Parse image registry hosts instead of substring matching so a benign
    # string containing "ghcr.io" cannot false-positive the check.
    for line in docker_workflow.splitlines():
        stripped = line.strip()
        if stripped.startswith("image:"):
            ref = stripped.split(":", 1)[1].strip().strip("'\"")
            registry = ref.split("/")[0] if "/" in ref else ""
            if registry == "ghcr.io" or registry.endswith(".ghcr.io"):
                fail("local-only Docker CI must not reference GHCR images")

    handler = (ROOT / "node-bridge" / "devassist420-handler.js").read_text(encoding="utf-8")
    for token in ("GOVERNED_CHAIN_NOT_CONNECTED", "output_authorized: false", "governedPipeline.ready === true"):
        if token not in handler:
            fail(f"DevAssist420 output gate missing required token: {token}")
    python_bridge = (ROOT / "bridge" / "server.py").read_text(encoding="utf-8")
    if "GOVERNED_CHAIN_NOT_CONNECTED" not in python_bridge or '"state": "YANK"' not in python_bridge:
        fail("direct Python WebSocket chat must YANK until the governed chain is connected")

    dashboard = (ROOT / canonical["dashboard"]).read_text(encoding="utf-8", errors="ignore")
    if "trimmed for brevity" in dashboard.lower():
        fail("canonical dashboard contains a truncated placeholder")
    print("runtime coherence passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
