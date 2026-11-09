"""
Asynchronous provider router with mandatory Gate + ComposedHeavyJudge gates.

No provider request is made until a Gate proof is verified. Provider fallback
is limited to transport failures. A candidate is released only after the
composed judge returns PASS and the dual-gate release evidence append succeeds.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

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
COUNCIL_LANES = ("grok", "gpt_codex", "claude")
REQUIRED_COUNCIL_LANES = frozenset(COUNCIL_LANES)
VALID_COUNCIL_ACTIONS = frozenset({"PASS", "REWRITE", "YANK"})


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
        self._council_adapter = None
        self._judge_provider_id: str | None = None
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
        council_adapter,
        judge_provider_id: str,
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
        if not callable(council_adapter):
            raise TypeError("a Council aggregation adapter is mandatory")
        if not isinstance(judge_provider_id, str) or not judge_provider_id.strip():
            raise ValueError("an independent Judge provider identity is mandatory")
        backend_provider_id = getattr(judge.backend, "provider_id", None)
        if not isinstance(backend_provider_id, str) or backend_provider_id != judge_provider_id:
            raise ValueError("Judge provider identity must match the injected Judge backend")

        self.judge = judge
        self._council_adapter = council_adapter
        self._judge_provider_id = judge_provider_id.strip()
        self._verification_key = authorization_verification_key
        self._owner_id = owner_id
        self._required_scope = tuple(required_scope)
        self._evidence_sink = evidence_sink

    @property
    def available_providers(self) -> list[str]:
        return list(self._providers.keys())

    def _append_evidence(self, event: dict[str, Any]) -> None:
        """Normalize dual-gate 5W1H events for the existing SCARLedgerSink contract."""
        if not callable(self._evidence_sink):
            raise RuntimeError("No SCAR evidence sink configured; output withheld")
        payload = dict(event)
        task_id = payload.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise RuntimeError("SCAR event requires task_id; output withheld")
        timestamp = payload.get("when")
        if not isinstance(timestamp, str) or not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        normalized = {
            **payload,
            "event": str(payload.get("what", "ASYNC_ROUTER_EVENT")),
            "timestamp": timestamp,
            "event_hash": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        }
        try:
            return self._evidence_sink(normalized)
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
                "network_accessed": "UNKNOWN",
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
                status_code = (
                    exc.response.status_code
                    if isinstance(exc, httpx.HTTPStatusError)
                    else None
                )
                retryable = isinstance(exc, httpx.TransportError) or (
                    status_code == 429 or (status_code is not None and 500 <= status_code <= 599)
                )
                self._append_evidence({
                    "who": "AIRouter",
                    "what": "PROVIDER_TRANSPORT_FAILURE" if retryable else "PROVIDER_TERMINAL_FAILURE",
                    "when": None,
                    "where": "backend.app.services.ai_router",
                    "why": "Retryable transport/server failure" if retryable else "Non-retryable provider failure; fallback prohibited",
                    "how": "exception class and HTTP status only; exception text and credentials excluded",
                    "authorization": claims.proof_id,
                    "memory_loaded": "UNKNOWN",
                    "network_accessed": "UNKNOWN",
                    "files_changed": [],
                    "result": "RETRY_NEXT_PROVIDER" if retryable else "STOP",
                    "task_id": task_id,
                    "provider": provider_name,
                    "error_type": type(exc).__name__,
                    "http_status": status_code,
                })
                if not retryable:
                    raise RuntimeError(
                        f"Provider {provider_name} failed non-retryably; output withheld"
                    ) from exc
                logger.warning(
                    "Provider %s transport failed (%s); trying next",
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

            # Council is the only path from provider proposals into the Judge.
            if not callable(self._council_adapter):
                raise RuntimeError("Council adapter is unavailable; output withheld")
            council = self._council_adapter({
                "task_id": task_id,
                "owner_id": claims.owner_id,
                "request": prompt,
                "candidate": candidate,
                "source_provider_id": provider_name,
                "context": context,
            })
            if not isinstance(council, Mapping):
                raise RuntimeError("Council returned an invalid aggregation; output withheld")
            council_action = str(council.get("action", "")).upper()
            council_candidate = council.get("candidate")
            source_provider_id = council.get("source_provider_id")
            proposals = council.get("proposals")
            votes = council.get("votes")
            if not isinstance(votes, Mapping) or not REQUIRED_COUNCIL_LANES.issubset(votes):
                raise RuntimeError("Council must provide all three lane votes")
            if council_action not in VALID_COUNCIL_ACTIONS:
                raise RuntimeError("Council aggregate action is missing or invalid; output withheld")
            if not isinstance(council_candidate, str) or not council_candidate.strip():
                raise RuntimeError("Council did not provide a consolidated candidate; output withheld")
            if not isinstance(proposals, Mapping) or not REQUIRED_COUNCIL_LANES.issubset(proposals):
                raise RuntimeError("Council must provide Grok, GPT/Codex, and Claude proposals")
            proposal_provider_ids = []
            for lane in COUNCIL_LANES:
                proposal = proposals[lane]
                if not isinstance(proposal, Mapping):
                    raise RuntimeError(f"Council proposal for {lane} is malformed")
                provider_id = proposal.get("provider_id")
                proposal_text = proposal.get("candidate")
                vote = str(proposal.get("vote", "")).upper()
                if not isinstance(provider_id, str) or not provider_id.strip():
                    raise RuntimeError(f"Council provider identity missing for {lane}")
                if not isinstance(proposal_text, str) or not proposal_text.strip():
                    raise RuntimeError(f"Council candidate missing for {lane}")
                if vote not in VALID_COUNCIL_ACTIONS:
                    raise RuntimeError(f"Council vote invalid for {lane}")
                if str(votes[lane]).upper() != vote:
                    raise RuntimeError(f"Council vote/proposal mismatch for {lane}")
                proposal_provider_ids.append(provider_id.strip())
            if len({item.casefold() for item in proposal_provider_ids}) != len(REQUIRED_COUNCIL_LANES):
                raise RuntimeError("Council lanes must have distinct provider identities")
            if not isinstance(source_provider_id, str) or not source_provider_id.strip():
                raise RuntimeError("Council source-provider identity is missing; output withheld")
            routed_proposal = next((item for item in proposals.values()
                                    if item["provider_id"].casefold() == provider_name.casefold()), None)
            if routed_proposal is None or routed_proposal["candidate"] != candidate:
                raise RuntimeError("Council omitted or altered the routed provider proposal")
            if source_provider_id != "council:aggregate":
                selected = next((item for item in proposals.values()
                                 if item["provider_id"].casefold() == source_provider_id.casefold()), None)
                if selected is None or selected["candidate"] != council_candidate:
                    raise RuntimeError("Council candidate/source binding mismatch")

            # Judge/evidence failures are terminal: never send the same task to another provider.
            review = self.judge.review(
                council_candidate,
                context,
                council_result={"action": council_action, **dict(council)},
                task_id=task_id,
                policy_hash=claims.policy_hash,
                judge_id=str(getattr(self.judge.backend, "model_id", "")),
                judge_provider_id=self._judge_provider_id,
                source_provider_id=source_provider_id,
                contributing_provider_ids=proposal_provider_ids,
            )
            verdict = review.get("verdict")
            if not isinstance(verdict, Mapping):
                raise RuntimeError("ComposedHeavyJudge returned a malformed verdict; output withheld")
            action = str(verdict.get("action", "")).upper()
            final_output = review.get("final_output")
            if action != "PASS" or not isinstance(final_output, str) or final_output != council_candidate:
                self._append_evidence({
                    "who": "AIRouter",
                    "what": "ESCROW_PENDING_REVIEW",
                    "when": None,
                    "where": "backend.app.services.ai_router",
                    "why": "ComposedHeavyJudge did not authorize exact candidate release",
                    "how": "non-PASS or changed output withheld; no provider fallback",
                    "authorization": claims.proof_id,
                    "memory_loaded": review.get("memory_loaded", "UNKNOWN"),
                    "network_accessed": review.get("network_accessed", "UNKNOWN"),
                    "files_changed": [],
                    "result": action or "YANK",
                    "task_id": task_id,
                    "provider": provider_name,
                    "output_hash": verdict.get("output_hash"),
                    "candidate_hash": verdict.get("candidate_hash"),
                    "policy_hash": claims.policy_hash,
                    "judge_id": verdict.get("judge_id"),
                    "source_provider_id": source_provider_id,
                })
                raise OutputWithheldError(
                    f"HeavyJudge action {action or 'UNKNOWN'}; provider output withheld"
                )

            memory_loaded = review.get("memory_loaded")
            judge_network_accessed = review.get("network_accessed")
            if not isinstance(memory_loaded, bool) or not isinstance(judge_network_accessed, bool):
                raise RuntimeError("ComposedHeavyJudge access telemetry is missing or malformed; output withheld")
            output_hash = verdict.get("output_hash")
            # Gate 2 verifies the exact output digest and commits evidence before release.
            receipt = verify_before_release(
                authorization_proof,
                {
                    "status": "PASS",
                    "output": final_output,
                    "output_hash": output_hash,
                    "judge_verdict": dict(verdict),
                    "source_provider_id": source_provider_id,
                },
                verification_key=self._verification_key,
                expected_task_id=task_id,
                expected_owner_id=self._owner_id,
                required_scope=self._required_scope,
                evidence_sink=self._append_evidence,
                memory_loaded=memory_loaded,
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
                "evidence_receipt": {
                    "event_type": receipt.evidence_receipt.event_type,
                    "task_id": receipt.evidence_receipt.task_id,
                    "event_id": receipt.evidence_receipt.event_id,
                    "event_hash": receipt.evidence_receipt.event_hash,
                    "signature": receipt.evidence_receipt.signature,
                    "sequence": receipt.evidence_receipt.sequence,
                },
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
