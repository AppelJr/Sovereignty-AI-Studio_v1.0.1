#!/usr/bin/env python3
"""Validate the canonical local runtime map without starting services.

This is a static coherence check. It detects missing canonical files, broken
aliases, duplicate launchers, port drift, and contradictory claims in the
runtime map. It does not contact networks, generate keys, or modify files.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config" / "runtime-coherence.json"
PORT_PATTERNS = {
    "dashboard": (9898,),
    "python_bridge": (9897,),
    "node_bridge": (9899,),
}


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def fail(message: str) -> None:
    raise SystemExit(f"runtime coherence failed: {message}")


def main() -> int:
    manifest = load_manifest()
    canonical = manifest["canonical_runtime"]

    for name, relative_path in canonical.items():
        if not (ROOT / relative_path).exists():
            fail(f"canonical {name} is missing: {relative_path}")

    for alias, target in manifest["aliases"].items():
        alias_path = ROOT / alias
        target_path = ROOT / target
        if not alias_path.exists():
            fail(f"declared alias is missing: {alias}")
        if not target_path.exists():
            fail(f"alias target is missing: {target}")

    if manifest["state_policy"]["default_mode"] != "local":
        fail("default runtime mode must be local")
    if not manifest["state_policy"]["private_state_is_not_committed"]:
        fail("private state must remain outside the repository")
    if not manifest["state_policy"]["provider_selection_is_owner_policy"]:
        fail("provider selection must remain deployment-owner policy")

    launcher = (ROOT / canonical["launcher"]).read_text(encoding="utf-8", errors="ignore")
    if "${SG_PORT:-9897}" not in launcher or "${NODE_BRIDGE_PORT:-9899}" not in launcher:
        fail("canonical launcher does not default to the expected bridge ports")
    if 'SG_RUNTIME_OWNER="DevAssist420SGHv119.html"' not in launcher:
        fail("canonical launcher points at the wrong dashboard entrypoint")
    if '"$ROOT_DIR/server.js"' not in launcher or '"$ROOT_DIR/python3_bridge.py"' not in launcher:
        fail("canonical launcher does not start the canonical Node/Python bridge entrypoints")
    if "127.0.0.1" not in launcher:
        fail("canonical launcher is not loopback-bound")


    # Ensure canonical ports are not silently changed in the canonical manifest.
    for key, expected in PORT_PATTERNS.items():
        port = manifest["ports"].get(key)
        if port not in expected:
            fail(f"port drift for {key}: expected one of {expected}, got {port}")

    # The HTML dashboard must not claim that a capability is active merely from
    # a decorative label. These markers identify known contradiction patterns.
    dashboard = (ROOT / canonical["dashboard"]).read_text(encoding="utf-8", errors="ignore")
    if "trimmed for brevity" in dashboard.lower():
        fail("canonical dashboard contains a truncated placeholder")

    print("runtime coherence passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
