#!/usr/bin/env python3
"""Live runner: executes real test files, streams results, writes evidence."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

TEST_FILES = [
    "test_sovereign_policy.py",
    "test_sovereign_agent.py",
    "test_policy_resolver.py",
    "test_security_boundary.py",
]


def run_file(path: Path) -> dict:
    start = time.time()
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(path), "-v", "--tb=line"],
        capture_output=True, text=True,
    )
    elapsed = time.time() - start
    passed = proc.returncode == 0
    lines = proc.stdout.splitlines()
    summary = lines[-1] if lines else ""
    return {
        "file": path.name,
        "passed": passed,
        "elapsed_ms": round(elapsed * 1000),
        "summary": summary,
        "stderr_tail": proc.stderr.splitlines()[-3:],
    }


def main():
    results = []
    for f in TEST_FILES:
        p = Path(f)
        if not p.exists():
            print(f"MISSING: {f}")
            continue
        print(f"RUNNING: {f} ...", flush=True)
        r = run_file(p)
        results.append(r)
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  {status}  {r['elapsed_ms']}ms  {r['summary']}", flush=True)

    all_pass = all(r["passed"] for r in results)
    evidence = {
        "event": "LIVE_RUN",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": results,
        "all_passed": all_pass,
    }
    Path("live_run_evidence.json").write_text(json.dumps(evidence, indent=2))
    print()
    print("ALL PASSED" if all_pass else "SOME FAILED")
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
