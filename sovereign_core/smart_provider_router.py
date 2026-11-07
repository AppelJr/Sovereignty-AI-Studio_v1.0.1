#!/usr/bin/env python3
"""DevAssist420 provider selection and mandatory Heavy Judge gate.

This module coordinates provider selection but does not authorize actions.
Gate.One remains the independent authorization boundary. Risk evaluation is
an injected dependency; missing or invalid evaluation fails closed.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

try:
    from .heavy_judge import HeavyJudge
except ImportError:
    from heavy_judge import HeavyJudge

logger = logging.getLogger("SmartProviderRouter")
COST_TIERS = {"xai": 1.0, "anthropic": 1.8, "openai": 2.2}


@dataclass
class RoutingDecision:
    provider: str
    reason: str
    remaining_capacity: int
    estimated_cost: float
    used_judge: bool = False


class SmartProviderRouter:
    """Select a provider, obtain its output, and always apply HeavyJudge."""

    def __init__(
        self,
        token_manager: Any,
        repmhl: Any | None = None,
        *,
        risk_evaluator: Callable[[str, str], float] | None = None,
        judge: HeavyJudge | None = None,
    ) -> None:
        if token_manager is None:
            raise ValueError("token_manager is required")
        self.token_manager = token_manager
        self.repmhl = repmhl
        self.config = getattr(token_manager, "config", {})
        self.risk_evaluator = risk_evaluator
        self.judge = judge or HeavyJudge(repmhl=repmhl, token_manager=token_manager)
        self.priority_rules = {
            "medical": ["anthropic", "xai", "openai"],
            "education": ["anthropic", "xai", "openai"],
            "general": ["xai", "anthropic", "openai"],
            "legal": ["anthropic", "openai", "xai"],
            "financial": ["openai", "anthropic", "xai"],
            "coding": ["openai", "xai", "anthropic"],
        }

    def _get_provider_capacity(self, provider: str) -> int:
        states = getattr(self.token_manager, "states", {})
        state = states.get(provider)
        if state is not None:
            return max(0, int(state.max_tokens) - int(state.token_count))
        providers = self.config.get("providers", {})
        cfg = providers.get(provider)
        if cfg is None:
            return 0
        return max(0, int(cfg.get("base_max_tokens", 0)))

    def route_request(
        self, text: str, context: str = "general", prefer_cheap: bool = True
    ) -> RoutingDecision:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if context not in self.priority_rules:
            raise ValueError(f"Unsupported routing context: {context!r}")
        priorities = list(self.priority_rules[context])
        if prefer_cheap:
            priorities.sort(key=lambda name: COST_TIERS.get(name, float("inf")))
        for provider in priorities:
            capacity = self._get_provider_capacity(provider)
            if capacity > 0:
                return RoutingDecision(
                    provider=provider,
                    reason=f"Available provider for context={context}",
                    remaining_capacity=capacity,
                    estimated_cost=COST_TIERS[provider],
                )
        raise RuntimeError("No configured provider has available capacity")

    def consume_with_routing(
        self,
        tokens: int,
        text: str = "",
        context: str = "general",
        use_judge: bool = True,
        prefer_cheap: bool = True,
    ) -> dict[str, Any]:
        """Route, obtain provider output, evaluate risk, and gate the output.

        use_judge remains for call-site compatibility but cannot disable the
        mandatory final gate.
        """
        del use_judge
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens <= 0:
            raise ValueError("tokens must be a positive integer")
        if self.risk_evaluator is None:
            raise RuntimeError("No trusted risk_evaluator configured; output withheld")
        decision = self.route_request(text, context, prefer_cheap)
        states = getattr(self.token_manager, "states", {})
        if decision.provider not in states:
            self.token_manager.start_session(decision.provider)
        model_result = self.token_manager.consume_tokens(decision.provider, tokens)
        if not isinstance(model_result, dict):
            raise TypeError("Provider token manager must return a result dictionary")
        original_output = model_result.get("output")
        if not isinstance(original_output, str):
            raise RuntimeError("Provider returned no textual output; output withheld")
        risk_score = self.risk_evaluator(original_output, context)
        judge_result = self.judge.review(
            original_output=original_output,
            context=context,
            risk_score=risk_score,
        )
        model_result["output"] = judge_result["final_output"]
        model_result["heavy_judge_verdict"] = judge_result["verdict"]
        model_result["heavy_judge_outcome"] = judge_result["outcome"]
        model_result.update(
            {
                "routed_to": decision.provider,
                "routing_reason": decision.reason,
                "used_judge": True,
                "estimated_cost_tier": decision.estimated_cost,
            }
        )
        return model_result
