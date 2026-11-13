from __future__ import annotations

import pytest

from ai_core.providers import devassist420_model


class FakeGGUF:
    def __init__(self, model_path=None):
        self.model_path = model_path
        self.calls = []

    def chat(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return "local DevAssist420 proposal"

    def health(self):
        return {
            "ok": True,
            "model_exists": True,
            "runtime_available": True,
            "loaded": False,
        }


def test_devassist_adapter_has_separate_provider_and_model_identity(monkeypatch):
    monkeypatch.setattr(devassist420_model, "GGUFProvider", FakeGGUF)
    adapter = devassist420_model.DevAssist420ModelAdapter("/models/devassist420.gguf")

    assert adapter.name == "local_gguf"
    assert adapter.provider_id == "local_gguf"
    assert adapter.model_id == "devassist420"
    assert adapter.network_accessed is False
    assert adapter._backend.model_path == "/models/devassist420.gguf"


def test_devassist_adapter_delegates_only_to_local_gguf(monkeypatch):
    monkeypatch.setattr(devassist420_model, "GGUFProvider", FakeGGUF)
    adapter = devassist420_model.DevAssist420ModelAdapter()
    messages = [{"role": "user", "content": "Review this proposal"}]

    result = adapter.chat(messages, max_tokens=128)

    assert result == "local DevAssist420 proposal"
    assert adapter._backend.calls == [
        (messages, {"context": None, "max_tokens": 128, "stream": False})
    ]


def test_devassist_adapter_health_is_truthful_and_network_free(monkeypatch):
    monkeypatch.setattr(devassist420_model, "GGUFProvider", FakeGGUF)
    result = devassist420_model.DevAssist420ModelAdapter().health()

    assert result == {
        "ok": True,
        "provider": "local_gguf",
        "model_id": "devassist420",
        "model_exists": True,
        "runtime_available": True,
        "loaded": False,
        "network_accessed": False,
    }


@pytest.mark.parametrize("messages", [None, [], "not-a-list"])
def test_devassist_adapter_rejects_invalid_messages(monkeypatch, messages):
    monkeypatch.setattr(devassist420_model, "GGUFProvider", FakeGGUF)
    adapter = devassist420_model.DevAssist420ModelAdapter()

    with pytest.raises(ValueError, match="messages"):
        adapter.chat(messages)


@pytest.mark.parametrize("max_tokens", [0, -1, True, 1.5])
def test_devassist_adapter_rejects_invalid_token_limits(monkeypatch, max_tokens):
    monkeypatch.setattr(devassist420_model, "GGUFProvider", FakeGGUF)
    adapter = devassist420_model.DevAssist420ModelAdapter()

    with pytest.raises(ValueError, match="max_tokens"):
        adapter.chat([{"role": "user", "content": "hello"}], max_tokens=max_tokens)


def test_sovereign_bridge_registers_devassist420_as_default_local_model(monkeypatch):
    from ai_core import sovereign_bridge

    created = {}

    class FakeAdapter(FakeGGUF):
        name = "local_gguf"
        model_id = "devassist420"

        def health(self):
            return {"ok": False, "provider": self.name, "model_id": self.model_id}

    monkeypatch.setattr(
        "ai_core.providers.devassist420_model.DevAssist420ModelAdapter",
        FakeAdapter,
    )
    bridge = sovereign_bridge.SovereignBridge(
        sovereign_model_path="/models/devassist420.gguf"
    )
    provider = bridge._get_provider("local_gguf")
    created["provider"] = provider

    assert isinstance(provider, FakeAdapter)
    assert provider.model_path == "/models/devassist420.gguf"
    assert bridge.health()["local_gguf"]["model_id"] == "devassist420"
