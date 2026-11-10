"""Tests for the bridge server WebSocket handling.

Uses lightweight protocol-compliant test transports instead of mocks.
"""
import json

import pytest

import bridge


class WSTransport:
    """Protocol-compliant in-process WebSocket transport for testing.

    Implements the same interface as a real websockets connection object
    (send, close, remote_address) so the bridge server can operate on it
    without any monkey-patching or mock frameworks.
    """

    def __init__(self, addr: tuple = ("127.0.0.1", 12345)):
        self.sent: list = []
        self.closed: bool = False
        self.remote_address: tuple = addr

    async def send(self, payload: str) -> None:
        self.sent.append(json.loads(payload))

    async def close(self) -> None:
        self.closed = True


class ServerHandle:
    """Protocol-compliant in-process server handle for testing.

    Mirrors the real asyncio server interface (close, wait_closed).
    """

    def __init__(self):
        self.closed: bool = False
        self.waited: bool = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.waited = True


@pytest.mark.asyncio
async def test_broadcast_ai_response_excludes_origin():
    srv = bridge.BridgeServer()
    sender = WSTransport()
    other = WSTransport()
    srv.clients = {sender, other}

    await srv.broadcast_ai_response("gpt", "hello", "ctx", exclude=sender)

    assert sender.sent == []
    assert len(other.sent) == 1
    payload = other.sent[0]
    assert payload["type"] == "ai_response"
    assert payload["agent"] == "gpt"
    assert payload["text"] == "hello"
    assert payload["context"] == "ctx"
    assert payload["hash"] == bridge.sha256("hello")


@pytest.mark.asyncio
async def test_ai_chat_withholds_output_until_governed_chain_is_connected(monkeypatch):
    srv = bridge.BridgeServer()
    ws = WSTransport()

    async def forbidden_candidate_generation(*_args, **_kwargs):
        raise AssertionError("ungoverned candidate generation must not run")

    monkeypatch.setattr(srv, "_chat_sovereign", forbidden_candidate_generation)
    await srv.ai_chat(ws, msg="hi", agent="sovereign", context="c1")

    assert len(ws.sent) == 1
    payload = ws.sent[0]
    assert payload["type"] == "ai_error"
    assert payload["state"] == "YANK"
    assert payload["action"] == "YANK"
    assert payload["error"] == "GOVERNED_CHAIN_NOT_CONNECTED"
    assert payload["output_authorized"] is False
    assert payload["escrow_required"] is True


@pytest.mark.asyncio
async def test_stop_closes_clients_and_server():
    srv = bridge.BridgeServer()
    ws1 = WSTransport()
    ws2 = WSTransport()
    srv.clients = {ws1, ws2}
    srv._server = ServerHandle()

    await srv.stop()

    assert srv._stopping is True
    assert ws1.closed is True
    assert ws2.closed is True
    assert srv.clients == set()
    assert srv._server.closed is True
    assert srv._server.waited is True


@pytest.mark.asyncio
async def test_local_provider_failure_does_not_attempt_http_fallback(monkeypatch):
    from ai_core import sovereign_bridge as sovereign_module

    class FailingLocalBridge:
        def chat(self, messages, **kwargs):
            raise RuntimeError("local model unavailable")

    monkeypatch.setattr(sovereign_module, "SovereignBridge", FailingLocalBridge)
    srv = bridge.BridgeServer()
    result = await srv._chat_sovereign("hello", "system", agent="devassist420")
    assert result == "[Sovereign bridge error: RuntimeError]"


def test_default_sovereign_provider_order_is_local_only(monkeypatch):
    import importlib
    from ai_core import sovereign_bridge as sovereign_module

    monkeypatch.delenv("SOVEREIGN_PROVIDER_ORDER", raising=False)
    importlib.reload(sovereign_module)
    assert sovereign_module._DEFAULT_ORDER == ["local_gguf"]


@pytest.mark.asyncio
async def test_local_bridge_is_cached_and_inference_readiness_is_truthful(monkeypatch):
    from ai_core import sovereign_bridge as sovereign_module

    created = {"count": 0}

    class CachedBridge:
        def __init__(self):
            created["count"] += 1
            self.loaded = False

        def health(self):
            return {
                "local_gguf": {
                    "ok": True,
                    "loaded": self.loaded,
                    "provider": "local_gguf",
                }
            }

        def chat(self, messages, **kwargs):
            self.loaded = True
            return "local-response"

    monkeypatch.setattr(sovereign_module, "SovereignBridge", CachedBridge)
    srv = bridge.BridgeServer()

    before = srv._inference_health()
    assert before["configured"] is True
    assert before["loaded"] is False
    assert before["ready"] is False

    first = await srv._chat_sovereign("hello", "system")
    second = await srv._chat_sovereign("again", "system")

    assert first == "local-response"
    assert second == "local-response"
    assert created["count"] == 1
    assert srv._inference_health()["ready"] is True
