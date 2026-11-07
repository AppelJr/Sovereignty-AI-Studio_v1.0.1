#!/usr/bin/env python3
"""Offline, fixed-allowlist dispatcher. No shell, network, or caller-selected executable."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import selectors
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

MAX_OUTPUT_BYTES = 64 * 1024
MAX_REQUEST_BYTES = 16 * 1024
TIMEOUT_SECONDS = 5.0
MAX_ARGS = 8
MAX_ARG_BYTES = 1024
EXECUTABLE = "/bin/echo"
TOOLS = {"echo": EXECUTABLE}


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _digest(value: bytes) -> str:
    return hashlib.sha3_512(value).hexdigest()


def _result(status: str, tool: str | None, **fields: Any) -> dict[str, Any]:
    return {"timestamp": utc_timestamp(), "tool": tool, "status": status, **fields}


def execute_tool_call(request: Any) -> dict[str, Any]:
    tool = request.get("tool") if isinstance(request, dict) else None
    if not isinstance(request, dict) or set(request) - {"tool", "args", "request_id"}:
        return _result("denied", tool if isinstance(tool, str) else None, reason="invalid request object")
    if not isinstance(tool, str) or tool not in TOOLS:
        return _result("denied", tool if isinstance(tool, str) else None, reason="tool is not allowlisted")
    args = request.get("args", [])
    if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
        return _result("error", tool, reason="args must be a list of strings")
    if len(args) > MAX_ARGS:
        return _result("error", tool, reason="too many arguments")
    if any("\x00" in arg or len(arg.encode("utf-8")) > MAX_ARG_BYTES for arg in args):
        return _result("error", tool, reason="argument is invalid or exceeds byte limit")

    executable = TOOLS[tool]
    if executable != EXECUTABLE or not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        return _result("error", tool, reason="pinned executable is unavailable or invalid")

    try:
        proc = subprocess.Popen(
            [EXECUTABLE, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except OSError as exc:
        return _result("error", tool, reason=f"process start failed: {type(exc).__name__}")

    assert proc.stdout is not None and proc.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
    selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    exceeded = False
    deadline = time.monotonic() + TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                proc.wait()
                return _result("error", tool, reason="tool timed out")
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                room = MAX_OUTPUT_BYTES - total
                if len(chunk) > room:
                    if room > 0:
                        buffers[key.data].extend(chunk[:room])
                        total += room
                    exceeded = True
                    proc.kill()
                    break
                buffers[key.data].extend(chunk)
                total += len(chunk)
            if exceeded:
                break
        proc.wait(timeout=max(0.1, deadline - time.monotonic()))
    except (OSError, subprocess.TimeoutExpired):
        proc.kill()
        proc.wait()
        return _result("error", tool, reason="tool I/O failed or timed out")
    finally:
        selector.close()
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass

    stdout, stderr = bytes(buffers["stdout"]), bytes(buffers["stderr"])
    fields = {
        "returncode": proc.returncode,
        "stdout_b64": base64.b64encode(stdout).decode("ascii"),
        "stderr_b64": base64.b64encode(stderr).decode("ascii"),
        "stdout_sha3_512": _digest(stdout),
        "stderr_sha3_512": _digest(stderr),
        "stdout_byte_length": len(stdout),
        "stderr_byte_length": len(stderr),
        "output_byte_length": total,
        "truncated": exceeded,
    }
    if exceeded:
        return _result("error", tool, reason="aggregate output limit exceeded; process stopped", **fields)
    return _result("success" if proc.returncode == 0 else "error", tool, **fields)


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        print(json.dumps(_result("error", None, reason="request exceeds byte limit")))
        return 2
    try:
        request = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        print(json.dumps(_result("error", None, reason="invalid JSON input")))
        return 2
    result = execute_tool_call(request)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result["status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
