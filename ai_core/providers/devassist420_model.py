"""
DevAssist420 local model adapter.

Identity separation is deliberate:
- provider/connector identity: local_gguf
- model identity: devassist420
- coordinator identity: DevAssist420 (defined by R-014; not a provider)

This adapter only wraps the existing device-local GGUF runtime. It does not
download weights, make network calls, authorize work, or release model output.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Generator, List, Optional

from .local_inference import GGUFProvider


class DevAssist420ModelAdapter:
    """Expose the DevAssist420 model through the local_gguf provider contract."""

    name = "local_gguf"
    provider_id = "local_gguf"
    model_id = "devassist420"
    network_accessed = False

    def __init__(self, model_path: Optional[str] = None) -> None:
        configured_path = (
            model_path
            or os.getenv("SOVEREIGN_DEVASSIST420_MODEL_PATH", "")
            or os.getenv("SOVEREIGN_MODEL_PATH", "")
        )
        self._backend = GGUFProvider(configured_path)

    def chat(
        self,
        messages: List[Dict[str, str]],
        *,
        context: Optional[Dict[str, str]] = None,
        max_tokens: int = 1200,
        stream: bool = False,
    ) -> str | Generator[str, None, None]:
        """Run local inference; no remote fallback is performed by this adapter."""
        if not isinstance(messages, list) or not messages:
            raise ValueError("messages must be a non-empty list")
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens < 1:
            raise ValueError("max_tokens must be a positive integer")
        return self._backend.chat(
            messages,
            context=context,
            max_tokens=max_tokens,
            stream=stream,
        )

    def health(self) -> Dict[str, Any]:
        """Report model readiness without loading weights or probing a network."""
        status = self._backend.health()
        return {
            "ok": status.get("ok") is True,
            "provider": self.provider_id,
            "model_id": self.model_id,
            "model_exists": status.get("model_exists") is True,
            "runtime_available": status.get("runtime_available") is True,
            "loaded": status.get("loaded") is True,
            "network_accessed": False,
        }
