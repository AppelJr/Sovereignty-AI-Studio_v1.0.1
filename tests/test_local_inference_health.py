import importlib.util

from ai_core.providers.local_inference import GGUFProvider, ONNXProvider


def test_gguf_health_requires_model_file_and_runtime(tmp_path, monkeypatch):
    missing = GGUFProvider(str(tmp_path / "missing.gguf"))
    result = missing.health()
    assert result["ok"] is False
    assert result["model_exists"] is False

    model = tmp_path / "devassist420-test.gguf"
    model.write_bytes(b"test-model-placeholder")
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object() if name == "llama_cpp" else None)
    configured = GGUFProvider(str(model))
    result = configured.health()
    assert result["ok"] is True
    assert result["loaded"] is False

    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: None)
    unavailable = GGUFProvider(str(model)).health()
    assert unavailable["model_exists"] is True
    assert unavailable["runtime_available"] is False
    assert unavailable["ok"] is False


def test_onnx_health_never_claims_ready_while_chat_is_unimplemented(tmp_path):
    model = tmp_path / "model.onnx"
    model.write_bytes(b"test-model-placeholder")
    result = ONNXProvider(str(model)).health()
    assert result["model_exists"] is True
    assert result["ok"] is False
    assert result["reason"] == "chat_not_implemented"
