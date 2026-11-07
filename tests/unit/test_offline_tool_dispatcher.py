import base64
import hashlib
import json
import subprocess
import sys
import os

from backend.integration.offline_tool_dispatcher import execute_tool_call

SCRIPT = Path(__file__).parents[2] / "backend" / "integration" / "offline_tool_dispatcher.py"


def test_echo_success_has_sha3_content_provenance():
    result = execute_tool_call({"tool": "echo", "args": ["sovereignty", "offline"]})
    output = base64.b64decode(result["stdout_b64"])
    assert result["status"] == "success"
    assert output == b"sovereignty offline\n"
    assert result["stdout_sha3_512"] == hashlib.sha3_512(output).hexdigest()
    assert result["stdout_byte_length"] == len(output)
    assert result["output_byte_length"] <= 64 * 1024


def test_unknown_tool_is_denied():
    result = execute_tool_call({"tool": "python", "args": ["-c", "print(1)"]})
    assert result["status"] == "denied"
    assert result["reason"] == "tool is not allowlisted"


def test_invalid_arguments_fail_closed():
    assert execute_tool_call({"tool": "echo", "args": ["x\x00y"]})["status"] == "error"
    assert execute_tool_call({"tool": "echo", "args": ["x"] * 9})["status"] == "error"
    assert execute_tool_call({"tool": "echo", "args": ["x" * 1025]})["status"] == "error"


def test_cli_returns_structured_json():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps({"tool": "echo", "args": ["cli"]}),
        text=True,
        capture_output=True,
        timeout=8,
        check=False,
    )
    result = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert result["status"] == "success"


def test_aggregate_output_cap_terminates_process(tmp_path, monkeypatch):
    import backend.integration.offline_tool_dispatcher as dispatcher

    producer = tmp_path / "producer"
    producer.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stdout.write('x' * (2 * 1024 * 1024))\n",
        encoding="utf-8",
    )
    producer.chmod(0o700)
    monkeypatch.setattr(dispatcher, "EXECUTABLE", str(producer))
    monkeypatch.setitem(dispatcher.TOOLS, "echo", str(producer))

    result = dispatcher.execute_tool_call({"tool": "echo", "args": []})

    assert result["status"] == "error"
    assert result["truncated"] is True
    assert result["output_byte_length"] == dispatcher.MAX_OUTPUT_BYTES
    assert result["reason"].startswith("aggregate output limit exceeded")
