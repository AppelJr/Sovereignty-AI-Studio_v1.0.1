#!/usr/bin/env python3
"""Fail-closed ARA repository/ruleset audit.

Audit only. Never changes rulesets, refs, files, credentials, or permissions.

Intentional non-product trees (external vendor dumps, venvs, build outputs)
are excluded from inventory risk findings so the gate does not permanently
fail on known layout. Real nested git, live credential files, and misconfigured
rulesets still fail closed.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = os.environ.get("GH_REPOSITORY", "AppelJr/Sovereignty-AI-Studio_v1.0.1")
BRANCH = os.environ.get("ARA_CANONICAL_BRANCH", "Collaboration")
RULESET = os.environ.get("ARA_RULESET_NAME", "Ara")
# Opt-in: only CRITICAL-fail when the named ruleset is required by policy.
REQUIRE_RULESET = os.environ.get("ARA_REQUIRE_RULESET", "0").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
REPORT = ROOT / "automation/reports/ara_full_audit.json"
# Non-product trees: never treat as repository integrity findings.
# NOTE: '.git' is intentionally NOT in this set. It names the repository's own
# git directory; nested '.git' directories are the thing being detected.
IGNORE = {
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    "external",  # vendor / skeleton dumps — not first-party product surface
}


def rel(p: Path) -> str:
    return p.relative_to(ROOT).as_posix()


def git(*args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return ""


def files():
    return sorted(
        p for p in ROOT.rglob("*") if p.is_file() and not any(x in IGNORE for x in p.parts)
    )


def digest(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def api(path: str, token: str):
    req = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def main() -> int:
    fs = files()
    buckets: dict[str, list[str]] = defaultdict(list)
    for p in fs:
        buckets[digest(p)].append(rel(p))
    dupes = [v for v in buckets.values() if len(v) > 1]

    # Nested git: any '.git' directory that is not the repository root's own.
    # Compare Path objects directly — do NOT use 'x in p.parts' against IGNORE,
    # because that would treat the literal directory name '.git' as an ignored
    # tree and silently skip the very thing we are looking for.
    nested = [
        rel(p.parent)
        for p in ROOT.rglob(".git")
        if p != ROOT / ".git" and not any(part in IGNORE for part in p.parts)
    ]

    # Snapshot paths that escaped IGNORE would still be reported; with external/
    # ignored this stays empty for the known SuperGrok skeleton layout.
    snapshots = [
        rel(p)
        for p in fs
        if "/Sovereignty-AI-Studio-main/" in rel(p) and rel(p).startswith("external/")
    ]

    templates: list[str] = []
    for p in fs:
        # Only scan first-party trees for credential-ish filenames.
        if any(part in IGNORE for part in p.parts):
            continue
        name = p.name.lower()
        if name == "dependabot.yaml" and "example.com" in p.read_text(errors="ignore"):
            templates.append(rel(p))
        # Live credential filenames only — not *.example templates.
        if p.name in {".env", ".env.local", ".env.production", "id_rsa", "id_ed25519"}:
            templates.append(rel(p))

    local = {
        "branch": git("branch", "--show-current"),
        "head": git("rev-parse", "HEAD"),
        "files_scanned": len(fs),
        "duplicate_groups": dupes,
        "nested_git_repositories": nested,
        "nested_studio_snapshot_paths": snapshots,
        "credential_or_template_risks": templates,
        "status": git("status", "--porcelain=v1").splitlines(),
    }

    remote: dict = {"checked": False}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        try:
            rs = api(f"/repos/{REPO}/rulesets", token)
            if isinstance(rs, list):
                matches = [
                    r
                    for r in rs
                    if isinstance(r, dict) and r.get("name", "").casefold() == RULESET.casefold()
                ]
            else:
                matches = []
            remote = {
                "checked": True,
                "matches": [api(f"/repos/{REPO}/rulesets/{r['id']}", token) for r in matches],
            }
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as e:
            remote = {"checked": False, "error": str(e)}

    findings: list[dict] = []
    if nested:
        findings.append({"severity": "HIGH", "code": "NESTED_REPOSITORY", "paths": nested})
    if snapshots:
        findings.append(
            {
                "severity": "HIGH",
                "code": "NESTED_STUDIO_SNAPSHOT",
                "paths": snapshots,
            }
        )
    if templates:
        findings.append(
            {"severity": "HIGH", "code": "CREDENTIAL_OR_TEMPLATE_RISK", "paths": templates}
        )
    if dupes:
        findings.append({"severity": "MEDIUM", "code": "DUPLICATE_CONTENT", "groups": len(dupes)})

    if remote.get("checked"):
        matches = remote.get("matches") or []
        if not matches:
            # Missing ruleset is informational unless explicitly required.
            severity = "CRITICAL" if REQUIRE_RULESET else "MEDIUM"
            findings.append(
                {
                    "severity": severity,
                    "code": "ARA_RULESET_MISSING",
                    "detail": (
                        f"No ruleset named {RULESET!r}. "
                        + (
                            "ARA_REQUIRE_RULESET=1 is set."
                            if REQUIRE_RULESET
                            else "Set ARA_REQUIRE_RULESET=1 after the ruleset exists."
                        )
                    ),
                }
            )
        for r in matches:
            if r.get("enforcement") != "active":
                findings.append({"severity": "CRITICAL", "code": "ARA_RULESET_DISABLED"})
            refs = (r.get("conditions") or {}).get("ref_name") or {}
            include = refs.get("include") or []
            if include and not any(BRANCH in x for x in include):
                findings.append(
                    {"severity": "HIGH", "code": "CANONICAL_BRANCH_NOT_COVERED"}
                )
            for b in r.get("bypass_actors") or []:
                if b.get("bypass_mode") == "always" and b.get("actor_id") is None:
                    findings.append({"severity": "CRITICAL", "code": "UNSCOPED_BYPASS"})

    result = {
        "repository": REPO,
        "canonical_branch": BRANCH,
        "ruleset": RULESET,
        "require_ruleset": REQUIRE_RULESET,
        "local": local,
        "remote_ruleset": remote,
        "findings": findings,
        "fail_closed": True,
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"findings": len(findings), "report": str(REPORT)}, indent=2))
    return 1 if any(x["severity"] in {"CRITICAL", "HIGH"} for x in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
