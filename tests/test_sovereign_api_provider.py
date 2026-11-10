import pytest

from ai_core.providers.sovereign_api import SovereignAPIProvider


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:9898/api/ai",
        "http://127.0.0.1:9899/api/ai",
        "http://[::1]:9897/api/ai",
        "http://backend:8002/api/ai",
        "http://node-bridge:9899/api/ai",
        "http://gateway:9001/api/ai",
    ],
)
def test_local_stack_api_urls_are_allowed(url):
    provider = SovereignAPIProvider(api_url=url)
    assert provider._api_url == url


@pytest.mark.parametrize(
    "url",
    [
        "https://api.openai.com/v1",
        "https://api.anthropic.com/v1",
        "https://api.x.ai/v1",
        "http://192.0.2.10:9899/api/ai",
        "http://localhost:9899/api/ai?redirect=https://example.com",
        "http://user:password@localhost:9899/api/ai",
        "file:///etc/passwd",
    ],
)
def test_external_or_ambiguous_api_urls_are_rejected(url):
    with pytest.raises(ValueError, match="approved loopback or internal service"):
        SovereignAPIProvider(api_url=url)


def test_default_api_url_is_loopback(monkeypatch):
    monkeypatch.delenv("SOVEREIGN_API_URL", raising=False)
    provider = SovereignAPIProvider()
    assert provider._api_url == "http://localhost:9898/api/ai"
