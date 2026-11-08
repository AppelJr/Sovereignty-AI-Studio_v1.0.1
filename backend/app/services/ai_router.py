"""
Asynchronous provider router with mandatory Gate + ComposedHeavyJudge gates.

No provider request is made until a Gate proof is verified. Provider fallback
is limited to transport failures. A candidate is released only after the
composed judge returns PASS and the dual-gate release evidence append succeeds.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Any, Optional

from app.services.providers.openai_provider import OpenAIProvider
from app.services.providers.anthropic_provider import AnthropicProvider
from app.services.providers.xai_provider import XAIProvider
from backend.coordination.dual_gate_path import (
    DualGateDenied,
    authorize_before_route,
    verify_before_release,
)
from sovereign_core.judge_composition import ComposedHeavyJudge

logger = logging.getLogger(__name__)
PROVIDER_ORDER = ["xai", "anthropic", "openai"]


class OutputWithheldError(PermissionError):
    """The provider candidate did not satisfy the complete release policy."""


class AIRouter:
    """Route provider requests through pre-route authorization and post-judge release."""

    def __init__(
        self,
        *,
        providers: Mapping[str, Any] | None = None,
    ) -> None:
        self._providers: dict[str, Any] = dict(providers or {})
        self.judge: ComposedHeavyJudge | None = None
        self._verification_key: bytes | None = None
        self._owner_id: str | None = None
        self._required_scope: tuple[str, ...] = ()
        self._evidence_sink = None
        if providers is None:
            self._init_providers()

    def _init_providers(self) -> None:
        """Initialize configured official provider adapters; this performs no probes."""
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
                    logger.warning(
                        "Failed to init provider %s: %s", name, type(exc).__name__
                    )

    def configure_governance(
        self,
        *,
        judge: ComposedHeavyJudge,
        authorization_verification_key: bytes,
        owner_id: str,
        required_scope: tuple[str, ...],
        evidence_sink,
    ) -> None:
        """Bind governance only after canonical owner/device startup validation."""
        if not isinstance(judge, ComposedHeavyJudge):
            raise TypeError("judge must be an injected ComposedHeavyJudge")
        if not isinstance(authorization_verification_key, bytes) or not authorization_verification_key:
            raise TypeError("authorization_verification_key must be non-empty bytes")
        if not isinstance(owner_id, str) or not owner_id.strip():
            raise ValueError("owner_id is required")
        if not required_scope or any(not isinstance(item, str) or not item for item in required_scope):
            raise ValueError("required_scope must contain explicit non-empty capabilities")
        if not callable(evidence_sink):
            raise TypeError("mandatory SCAR evidence_sink is required")

        self.judge = judge
        self._verification_key = authorization_verification_key
        self._owner_id = owner_id
        self._required_scope = tuple(required_scope)
        self._evidence_sink = evidence_sink

    @property
    def available_providers(self) -> list[str]:
        return list(self._providers.keys())

    def _append_evidence(self, event: dict[str, Any]) -> None:
        if not callable(self._evidence_sink):
            raise RuntimeError("No SCAR evidence sink configured; output withheld")
        try:
            self._evidence_sink(event)
        except Exception as exc:
            raise RuntimeError("Mandatory SCAR evidence append failed; output withheld") from exc

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
        *,
        authorization_proof: str | Mapping[str, Any] | None = None,
        task_id: str | None = None,
    ) -> dict[str, Any]:
        """Run a provider request only inside the verified dual-gate boundary."""
        if privacy_mode:
            raise RuntimeError(
                "Privacy mode enabled: external AI calls are not permitted."
            )
        if self.judge is None or self._verification_key is None:
            raise RuntimeError("Governance startup state is unbound; output withheld")
        if self._owner_id is None or not callable(self._evidence_sink):
            raise RuntimeError("Owner identity or SCAR evidence sink is unbound; output withheld")
        if not isinstance(authorization_proof, (str, Mapping)) or not authorization_proof:
            raise DualGateDenied("a Gate authorization proof is required before provider routing")
        if not isinstance(task_id, str) or not task_id.strip():
            raise DualGateDenied("an authorized task_id is required before provider routing")
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt must be a non-empty string")

        # Gate 1 is deliberately before provider selection, health probing, or execution.
        claims = authorize_before_route(
            authorization_proof,
            verification_key=self._verification_key,
            task_id=task_id,
            owner_id=self._owner_id,
            required_scope=self._required_scope,
        )
        self._append_evidence({
            "who": "AIRouter",
            "what": "GATE_AUTHORIZATION_ACCEPTED",
            "when": claims.issued_at,
            "where": "backend.app.services.ai_router",
            "why": "Gate proof verified for owner, task, scope, and expiry",
            "how": "cryptographic Gate proof verification before provider routing",
            "authorization": claims.proof_id,
            "memory_loaded": "UNKNOWN",
            "network_accessed": False,
            "files_changed": [],
            "result": "ALLOW",
            "task_id": task_id,
            "policy_hash": claims.policy_hash,
        })

        errors: list[dict[str, str]] = []
        for provider_name in self._build_order(preferred_provider):
            provider = self._providers.get(provider_name)
            if provider is None:
                continue

            self._append_evidence({
                "who": "AIRouter",
                "what": "PROVIDER_ATTEMPT",
                "when": None,
                "where": "backend.app.services.ai_router",
                "why": "Gate authorization accepted; provider selected by configured fallback order",
                "how": "provider chat request; prompt and credentials excluded from evidence",
                "authorization": claims.proof_id,
                "memory_loaded": "UNKNOWN",
                "network_accessed": True,
                "files_changed": [],
                "result": "ATTEMPT",
                "task_id": task_id,
                "provider": provider_name,
            })
            kwargs: dict[str, Any] = {
                "prompt": prompt,
                "system": system,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
            if model:
                kwargs["model"] = model

            try:
                provider_result = await provider.chat(**kwargs)
            except Exception as exc:
                self._append_evidence({
                    "who": "AIRouter",
                    "what": "PROVIDER_TRANSPORT_FAILURE",
                    "when": None,
                    "where": "backend.app.services.ai_router",
                    "why": "Provider transport failed; fallback is limited to this failure class",
                    "how": "exception type recorded; exception text and credentials excluded",
                    "authorization": claims.proof_id,
                    "memory_loaded": "UNKNOWN",
                    "network_accessed": True,
                    "files_changed": [],
                    "result": "RETRY_NEXT_PROVIDER",
                    "task_id": task_id,
                    "provider": provider_name,
                    "error_type": type(exc).__name__,
                })
                logger.warning(
                    "Provider %s failed (%s); trying next",
                    provider_name,
                    type(exc).__name__,
                )
                errors.append({"provider": provider_name, "error": type(exc).__name__})
                continue

            # A malformed successful response is not a transport failure and cannot trigger fallback.
            if not isinstance(provider_result, Mapping) or not isinstance(provider_result.get("text"), str):
                raise RuntimeError(
                    f"Provider {provider_name} returned malformed output; output withheld"
                )
            candidate = provider_result["text"]
            if not candidate.strip():
                raise RuntimeError(
                    f"Provider {provider_name} returned empty output; output withheld"
                )

            # Judge/evidence failures are terminal: never send the same task to another provider.
            review = self.judge.review(candidate, context)
            verdict = review.get("verdict")
            if not isinstance(verdict, Mapping):
                raise RuntimeError("ComposedHeavyJudge returned a malformed verdict; output withheld")
            action = str(verdict.get("action", "")).upper()
            final_output = review.get("final_output")
            if action != "PASS" or not isinstance(final_output, str) or final_output != candidate:
                self._append_evidence({
                    "who": "AIRouter",
                    "what": "ESCROW_PENDING_REVIEW",
                    "when": None,
                    "where": "backend.app.services.ai_router",
                    "why": "ComposedHeavyJudge did not authorize exact candidate release",
                    "how": "non-PASS or changed output withheld; no provider fallback",
                    "authorization": claims.proof_id,
                    "memory_loaded": review.get("memory_loaded", "UNKNOWN"),
                    "network_accessed": True,
                    "files_changed": [],
                    "result": action or "YANK",
                    "task_id": task_id,
                    "provider": provider_name,
                    "output_hash": verdict.get("output_hash"),
                })
                raise OutputWithheldError(
                    f"HeavyJudge action {action or 'UNKNOWN'}; provider output withheld"
                )

            output_hash = verdict.get("output_hash")
            # Gate 2 verifies the exact output digest and commits evidence before release.
            receipt = verify_before_release(
                claims,
                {
                    "status": "PASS",
                    "output": final_output,
                    "output_hash": output_hash,
                },
                expected_task_id=task_id,
                evidence_sink=self._append_evidence,
                memory_loaded=review.get("memory_loaded") is True,
                # This router's configured providers are remote APIs; the call used the network.
                network_accessed=True,
            )

            result = dict(provider_result)
            result["text"] = receipt.output
            result["heavy_judge_verdict"] = dict(verdict)
            result["heavy_judge_outcome"] = "PASS"
            result["judge_model"] = verdict.get("judge_model", "unknown")
            result["release_receipt"] = {
                "task_id": receipt.task_id,
                "authorization_proof_id": receipt.authorization_proof_id,
                "authorization_policy_hash": receipt.authorization_policy_hash,
                "output_hash": receipt.output_hash,
                "release_status": receipt.release_status,
            }
            if errors:
                result["fallback_from"] = errors
            return result

        raise RuntimeError(
            "All configured AI providers failed. "
            f"Provider errors: {errors}. Available: {self.available_providers}"
        )

    def _build_order(self, preferred: Optional[str]) -> list[str]:
        order = PROVIDER_ORDER.copy()
        if preferred and preferred in self._providers:
            order = [preferred] + [name for name in order if name != preferred]
        return order

    async def health_check(self) -> dict[str, Any]:
        """Return local configuration only; do not probe providers without Gate proof."""
        return {
            "router": "sovereign",
            "providers": {
                name: {"configured": True, "probe_performed": False}
                for name in self._providers
            },
            "available": list(self._providers),
            "network_accessed": False,
        }


# Deliberately unconfigured until canonical owner startup injects Gate and evidence state.
ai_router = AIRouter()
