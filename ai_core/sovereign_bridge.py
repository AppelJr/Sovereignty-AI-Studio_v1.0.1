"""
Sovereignty AI Studio — Sovereign Bridge (Python side)
Routes local inference through the DevAssist420 model participant.
No external SaaS. Local GGUF is the default and does not use network transport.
"""
from __future__ import annotations

import os
import time
import logging
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)

# Local-only by default. Remote adapters require explicit owner configuration.
_DEFAULT_ORDER = os.getenv("SOVEREIGN_PROVIDER_ORDER", "local_gguf").split(",")


class ProviderError(RuntimeError):
    """Raised when all configured sovereign providers fail."""


class SovereignBridge:
    """Route inference to explicitly configured sovereign model adapters."""

    def __init__(
        self,
        provider_order: Optional[List[str]] = None,
        *,
        sovereign_model_path: Optional[str] = None,
        sovereign_onnx_path: Optional[str] = None,
        sovereign_api_url: Optional[str] = None,
    ):
        self._order = provider_order or _DEFAULT_ORDER
        self._cfg = {
            "model_path": (
                sovereign_model_path
                or os.getenv("SOVEREIGN_DEVASSIST420_MODEL_PATH")
                or os.getenv("SOVEREIGN_MODEL_PATH")
            ),
            "onnx_path": sovereign_onnx_path or os.getenv("SOVEREIGN_ONNX_PATH"),
            "api_url": sovereign_api_url or os.getenv(
                "SOVEREIGN_API_URL", "http://localhost:9898/api/ai"
            ),
        }
        self._providers: Dict[str, Any] = {}

    def chat(
        self,
        messages: List[Dict[str, str]],
        *,
        context: Optional[Dict[str, str]] = None,
        max_tokens: int = 1200,
        stream: bool = False,
    ) -> str | Generator[str, None, None]:
        """Execute in configured order; local GGUF failures never fall back remotely."""
        context = context or {}
        for provider_name in self._order:
            provider_name = provider_name.strip()
            try:
                provider = self._get_provider(provider_name)
                logger.info(
                    "Trying provider=%s model=%s",
                    provider_name,
                    getattr(provider, "model_id", "unspecified"),
                )
                return provider.chat(
                    messages,
                    context=context,
                    max_tokens=max_tokens,
                    stream=stream,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Provider %s failed: %s", provider_name, type(exc).__name__)
                # A local model failure is terminal: no implicit remote fallback.
                if provider_name == "local_gguf":
                    raise ProviderError(
                        "DevAssist420 local inference unavailable; remote fallback denied"
                    ) from exc
                raise ProviderError(
                    f"Configured sovereign provider {provider_name!r} failed"
                ) from exc
        raise ProviderError("No sovereign model providers are configured")

    def health(self) -> Dict[str, Any]:
        """Report local readiness without downloading weights or probing a network."""
        status: Dict[str, Any] = {}
        for name in self._order:
            name = name.strip()
            try:
                status[name] = self._get_provider(name).health()
            except Exception as exc:  # noqa: BLE001
                status[name] = {"ok": False, "error_type": type(exc).__name__}
        return status

    def _get_provider(self, name: str) -> Any:
        if name not in self._providers:
            self._providers[name] = self._load_provider(name)
        return self._providers[name]

    def _load_provider(self, name: str) -> Any:
        if name == "local_gguf":
            from ai_core.providers.devassist420_model import DevAssist420ModelAdapter

            return DevAssist420ModelAdapter(self._cfg["model_path"])
        if name == "local_onnx":
            from ai_core.providers.local_inference import ONNXProvider

            return ONNXProvider(self._cfg["onnx_path"])
        if name == "sovereign_api":
            from ai_core.providers.sovereign_api import SovereignAPIProvider

            return SovereignAPIProvider(self._cfg["api_url"])
        raise ValueError(f"Unknown sovereign provider: {name!r}")


def track_usage(
    user_id: str,
    org_id: str,
    tokens: int,
    provider: str,
    project_id: Optional[str] = None,
) -> None:
    """Record token usage — delegates to analytics.usage_tracker."""
    try:
        from analytics.usage_tracker import record_usage

        record_usage(
            user_id=user_id,
            org_id=org_id,
            tokens=tokens,
            provider=provider,
            project_id=project_id,
            ts=time.time(),
        )
    except ImportError:
        logger.debug("analytics.usage_tracker not available; skipping usage record")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Usage tracking failed: %s", type(exc).__name__)
