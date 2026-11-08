"""
Multi-provider AI router with provider fallback and a mandatory Heavy Judge gate.

Provider fallback handles transport/provider failures only. Once a provider
returns a candidate, the result is evaluated and audited exactly once; judge
or audit failures are never treated as provider failures and never trigger
another external call. Gate.One remains the separate authorization boundary.
"""
import logging
import os
from collections.abc import Callable
from typing import Optional, Any

from app.services.providers.openai_provider import OpenAIProvider
from app.services.providers.anthropic_provider import AnthropicProvider
from app.services.providers.xai_provider import XAIProvider
from sovereign_core.heavy_judge import HeavyJudge

logger = logging.getLogger(__name__)
PROVIDER_ORDER = ["xai", "anthropic", "openai"]


class AIRouter:
    """Route to configured providers, then enforce the mandatory Heavy Judge."""

    def __init__(
        self,
        *,
        risk_evaluator: Callable[[str, str], float] | None = None,
        repmhl: Any | None = None,
        judge: HeavyJudge | None = None,
    ) -> None:
        self._providers: dict = {}
        self.risk_evaluator = risk_evaluator
        self.repmhl = repmhl
        self.judge = judge or HeavyJudge(repmhl=repmhl)
        self._init_providers()

    def _init_providers(self) -> None:
        """Initialize configured official provider adapters."""
        candidates = {
            "xai": (XAIProvider, "XAI_API_KEY"),
            "anthropic": (AnthropicProvider, "ANTHROPIC_API_KEY"),
            "openai": (OpenAIProvider, "OPENAI_API_KEY"),
        }
        for name, (cls, env_key) in candidates.items():
            if os.getenv(env_key):
                try:
                    self._providers[name] = cls()
                    logger.info("AI provider initialized: %s", name)
                except Exception as exc:
                    logger.warning("Failed to init provider %s: %s", name, type(exc).__name__)

    def configure_governance(
        self,
        *,
        risk_evaluator: Callable[[str, str], float],
        repmhl: Any,
        judge: HeavyJudge | None = None,
    ) -> None:
        """Install startup-validated evaluator and persistent audit sink.

        Call only after canonical device-owner startup state has been validated.
        This method configures content governance; it does not grant Gate.One
        authorization or establish provider credentials.
        """
        if not callable(risk_evaluator):
            raise TypeError("risk_evaluator must be callable")
        audit_log = getattr(repmhl, "log", None)
        if not callable(audit_log):
            raise TypeError("repmhl must implement log(dict)")
        selected_judge = judge or HeavyJudge(repmhl=repmhl)
        if getattr(selected_judge, "repmhl", None) is not repmhl:
            raise ValueError("judge must use the configured REPMHL audit sink")
        self.risk_evaluator = risk_evaluator
        self.repmhl = repmhl
        self.judge = selected_judge

    @property
    def available_providers(self) -> list:
        return list(self._providers.keys())

    async def chat(
        self,
        prompt: str,
        system: str = "You are a helpful AI assistant.",
        preferred_provider: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        privacy_mode: bool = False,
        context: str = "general",
    ) -> dict:
        """Provider fallback followed by a mandatory, fail-closed judge gate."""
        if privacy_mode:
            raise RuntimeError(
                "Privacy mode enabled: external AI calls are not permitted. "
                "Configure a permitted sovereign local inference node."
            )
        if self.risk_evaluator is None:
            raise RuntimeError("No trusted risk_evaluator configured; output withheld")
        if self.repmhl is None:
            raise RuntimeError("No required REPMHL audit sink configured; output withheld")

        order = self._build_order(preferred_provider)
        errors: list = []
        for provider_name in order:
            provider = self._providers.get(provider_name)
            if provider is None:
                continue
            kwargs: dict = {
                "prompt": prompt,
                "system": system,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
            if model:
                kwargs["model"] = model
            try:
                result = await provider.chat(**kwargs)
            except Exception as exc:
                # Fail over only on provider/transport failure.
                logger.warning(
                    "Provider %s failed (%s); trying next",
                    provider_name,
                    type(exc).__name__,
                )
                errors.append({"provider": provider_name, "error": type(exc).__name__})
                continue

            if not isinstance(result, dict) or not isinstance(result.get("text"), str):
                raise RuntimeError(
                    f"Provider {provider_name} returned malformed output; output withheld"
                )

            candidate = result["text"]
            risk_score = self.risk_evaluator(candidate, context)
            verdict = self.judge.review(candidate, context, risk_score)
            result["text"] = verdict["final_output"]
            result["heavy_judge_verdict"] = verdict["verdict"]
            result["heavy_judge_outcome"] = verdict["outcome"]
            result["judge_model"] = verdict["judge_model"]
            if errors:
                result["fallback_from"] = errors
            return result

        raise RuntimeError(
            "All configured AI providers failed. "
            f"Provider errors: {errors}. Available: {self.available_providers}"
        )

    def _build_order(self, preferred: Optional[str]) -> list:
        order = PROVIDER_ORDER.copy()
        if preferred and preferred in self._providers:
            order = [preferred] + [provider for provider in order if provider != preferred]
        return order

    async def health_check(self) -> dict:
        status = {}
        for name, provider in self._providers.items():
            try:
                status[name] = {"healthy": await provider.health_check()}
            except Exception as exc:
                status[name] = {"healthy": False, "error": type(exc).__name__}
        return {
            "router": "sovereign",
            "providers": status,
            "available": list(status.keys()),
        }


# Deliberately unconfigured singleton fails closed until trusted evaluator and
# persistent REPMHL sink are injected by validated device startup state.
ai_router = AIRouter()
