#!/usr/bin/env python3
"""Gate-bound smart provider router with mandatory composed Heavy Judge.

The router is not an authority. A verified Gate proof is required before any
provider route; a composed judge PASS and durable release evidence are required
before output is returned. The judge is injected by validated owner startup.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any, Callable, Mapping

from backend.coordination.dual_gate_path import run_dual_gated
from sovereign_core.judge_composition import ComposedHeavyJudge

COST_TIERS = {"xai": 1.0, "anthropic": 1.8, "openai": 2.2}
REQUIRED_COUNCIL_LANES = frozenset({"grok", "gpt_codex", "claude"})
VALID_COUNCIL_ACTIONS = frozenset({"PASS", "REWRITE", "YANK"})


@dataclass(frozen=True, slots=True)
class RoutingDecision:
    provider: str
    reason: str
    remaining_capacity: int
    estimated_cost: float
    used_judge: bool = False


class EscrowPending(RuntimeError):
    """Candidate was withheld for second review or approved repair."""


class EvidenceWriteError(RuntimeError):
    """Mandatory evidence could not be persisted."""


class SmartProviderRouter:
    """Context-aware provider selection with mandatory dual-gate release."""

    def __init__(
        self,
        token_manager: Any,
        *,
        council_adapter: Callable[[dict[str, Any]], Mapping[str, Any]],
        judge: ComposedHeavyJudge,
        judge_identity: str | None = None,
        provider_id: str | None = None,
    ) -> None:
        if not callable(council_adapter):
            raise TypeError("a real three-lane council_adapter is mandatory")
        if not isinstance(judge, ComposedHeavyJudge):
            raise TypeError("a configured ComposedHeavyJudge is mandatory; no legacy bypass")
        judge_identity = str(judge_identity or getattr(judge, "judge_id", "")).strip() or None
        if judge_identity is not None and provider_id is not None and judge_identity == provider_id:
            raise ValueError("judge identity must be independent of the provider identity")
        self.token_manager = token_manager
        self.config = token_manager.config
        self.judge = judge
        self.council_adapter = council_adapter
        self.judge_identity = judge_identity
        self.provider_id = str(provider_id).strip() or None
        self.priority_rules = {
            "medical": ["anthropic", "xai", "openai"],
            "education": ["anthropic", "xai", "openai"],
            "general": ["xai", "anthropic", "openai"],
            "coding": ["openai", "anthropic", "xai"],
            "legal": ["anthropic", "openai", "xai"],
            "financial": ["openai", "anthropic", "xai"],
            "security": ["openai", "xai", "anthropic"],
        }

    def _get_provider_capacity(self, provider: str) -> int:
        state = self.token_manager.states.get(provider)
        if not state:
            cfg = self.config["providers"].get(provider)
            if not isinstance(cfg, Mapping):
                return 0
            return int(cfg.get("base_max_tokens", 0))
        return max(0, int(state.max_tokens) - int(state.token_count))

    def route_request(
        self, text: str, context: str = "general", prefer_cheap: bool = True
    ) -> RoutingDecision:
        del text, prefer_cheap
        priorities = self.priority_rules.get(context, self.priority_rules["general"])
        for provider in priorities:
            capacity = self._get_provider_capacity(provider)
            if capacity > 512:
                return RoutingDecision(
                    provider=provider,
                    reason=f"Best available for context={context}",
                    remaining_capacity=capacity,
                    estimated_cost=COST_TIERS.get(provider, 2.0),
                )
        raise RuntimeError("no provider has sufficient configured capacity; refusing fallback")

    def consume_with_routing(
        self,
        tokens: int,
        text: str,
        *,
        context: str,
        authorization_proof: str,
        verification_key: bytes,
        task_id: str,
        owner_id: str,
        required_scope: tuple[str, ...],
        evidence_sink: Callable[[dict[str, Any]], Any],
        prefer_cheap: bool = True,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Route only after Gate 1; release only after judge PASS and Gate 2.

        Council votes must be attributable and complete. Every non-PASS judge
        result is escrowed and withheld. Judge, provider, and evidence errors
        propagate; they never trigger an unapproved provider fallback.
        """
        if not callable(evidence_sink):
            raise TypeError("evidence_sink is mandatory")
        execution: dict[str, Any] = {}

        def route_and_judge(_verified_claims: Any) -> Mapping[str, Any]:
            decision = self.route_request(text, context, prefer_cheap)
            if decision.provider not in self.token_manager.states:
                self.token_manager.start_session(decision.provider)
            model_result = self.token_manager.consume_tokens(decision.provider, tokens)
            if not isinstance(model_result, Mapping):
                raise RuntimeError("provider returned invalid result")
            candidate = model_result.get("output")
            if not isinstance(candidate, str) or not candidate.strip():
                raise RuntimeError("provider returned no candidate output; refusing placeholder")

            council = self.council_adapter({
                "task_id": task_id,
                "owner_id": owner_id,
                "request": text,
                "candidate": candidate,
                "context": context,
                "route": asdict(decision),
            })
            if not isinstance(council, Mapping):
                raise RuntimeError("Council returned invalid result")
            votes = council.get("votes")
            if not isinstance(votes, Mapping) or not REQUIRED_COUNCIL_LANES.issubset(votes):
                raise RuntimeError("Council must provide all three lanes: Grok, GPT/Codex and Claude votes")
            if any(str(votes[lane]).upper() not in VALID_COUNCIL_ACTIONS
                   for lane in REQUIRED_COUNCIL_LANES):
                raise RuntimeError("Council contains unsupported lane action")
            if str(council.get("action", "")).upper() not in VALID_COUNCIL_ACTIONS:
                raise RuntimeError("Council aggregate action is missing or unsupported")

            candidate_hash = "sha3-512:" + hashlib.sha3_512(candidate.encode("utf-8")).hexdigest()
            judged = self.judge.review(
                original_output=candidate,
                context=context,
                force_judge=True,
                council_result=council,
                task_id=task_id,
                policy_hash=_verified_claims.policy_hash,
                candidate_hash=candidate_hash,
                judge_id=self.judge_identity,
            )
            if not isinstance(judged, Mapping):
                raise RuntimeError("ComposedHeavyJudge returned invalid result")
            verdict = judged.get("verdict")
            action = str(verdict.get("action", "")).upper() if isinstance(verdict, Mapping) else ""
            if action != "PASS":
                event = {
                    "who": "SmartProviderRouter",
                    "what": "ESCROW_PENDING_REVIEW",
                    "when": datetime.now(timezone.utc).isoformat(),
                    "where": "Sovereignty-AI-Studio_v1.0.1",
                    "why": "Council or composed Heavy Judge did not return PASS",
                    "how": "provider -> three-lane Council -> composed Heavy Judge",
                    "authorization": "pre-route-gate-verified",
                    "memory_loaded": False,
                    "network_accessed": True,
                    "files_changed": [],
                    "result": "YANK",
                    "task_id": task_id,
                    "judge_verdict": dict(verdict) if isinstance(verdict, Mapping) else {},
                    "council": dict(council),
                }
                try:
                    evidence_sink(event)
                except Exception as exc:
                    raise EvidenceWriteError("escrow evidence append failed") from exc
                execution.update({
                    "status": "ESCROW_PENDING_REVIEW",
                    "action": action,
                    "council": dict(council),
                    "judge_verdict": dict(verdict) if isinstance(verdict, Mapping) else {},
                })
                raise EscrowPending(f"{action or 'INVALID'} requires second review")

            output = judged.get("final_output")
            if not isinstance(output, str) or not output.strip() or output != candidate:
                raise RuntimeError("Heavy Judge PASS did not preserve the validated candidate")
            output_hash = "sha3-512:" + hashlib.sha3_512(output.encode("utf-8")).hexdigest()
            execution.update({
                "status": "PASS",
                "output": output,
                "output_hash": output_hash,
                "routed_to": decision.provider,
                "routing_reason": decision.reason,
                "council": dict(council),
                "judge_verdict": dict(verdict),
            })
            return {"status": "PASS", "output": output, "output_hash": output_hash, "judge_verdict": dict(verdict)}

        try:
            receipt = run_dual_gated(
                proof=authorization_proof,
                verification_key=verification_key,
                task_id=task_id,
                owner_id=owner_id,
                required_scope=required_scope,
                route_and_judge=route_and_judge,
                evidence_sink=evidence_sink,
                now=now,
                memory_loaded=False,
                network_accessed=True,
            )
        except EscrowPending:
            return execution
        return {
            **execution,
            "status": receipt.release_status,
            "output": receipt.output,
            "output_hash": receipt.output_hash,
            "authorization_proof_id": receipt.authorization_proof_id,
            "policy_hash": receipt.authorization_policy_hash,
            "used_judge": True,
        }


__all__ = [
    "EscrowPending",
    "EvidenceWriteError",
    "RoutingDecision",
    "SmartProviderRouter",
]

