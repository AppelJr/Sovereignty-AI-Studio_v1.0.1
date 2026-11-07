#!/usr/bin/env python3
"""DevAssist420 Heavy Judge: deterministic policy gate for model proposals.

Risk scores are supplied by an explicitly configured evaluator; this class
does not pretend keyword heuristics are a calibrated safety model. Rewriter
output is untrusted and is accepted only after a separate rewrite evaluator
scores it below the context rewrite threshold. Gate.One remains the independent
authorization boundary.
"""
from __future__ import annotations

import hashlib
import hmac
import math
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any


class HeavyJudge:
    """Apply context thresholds and emit a REPMHL-compatible audit event."""

    DEFAULT_POLICIES: dict[str, dict[str, float]] = {
        "medical": {"rewrite_at": 0.75, "yank_at": 0.90},
        "education": {"rewrite_at": 0.75, "yank_at": 0.90},
        "general": {"rewrite_at": 0.75, "yank_at": 0.90},
        "legal": {"rewrite_at": 0.75, "yank_at": 0.90},
        "financial": {"rewrite_at": 0.75, "yank_at": 0.90},
        "coding": {"rewrite_at": 0.75, "yank_at": 0.90},
    }

    def __init__(
        self,
        model_name: str = "SuperGrok-5.7-Hybrid",
        repmhl: Any | None = None,
        *,
        rewriter: Callable[[str, str], str] | None = None,
        rewrite_risk_evaluator: Callable[[str, str], float] | None = None,
        policies: Mapping[str, Mapping[str, float]] | None = None,
        audit_hmac_key: bytes | None = None,
        fail_closed_on_log_error: bool = True,
    ) -> None:
        if audit_hmac_key is not None and (
            not isinstance(audit_hmac_key, bytes) or not audit_hmac_key
        ):
            raise ValueError("audit_hmac_key must be non-empty bytes")
        self.model = model_name
        self.repmhl = repmhl
        self.rewriter = rewriter
        self.rewrite_risk_evaluator = rewrite_risk_evaluator
        self.audit_hmac_key = audit_hmac_key
        self.fail_closed_on_log_error = fail_closed_on_log_error
        self.policies = self._validate_policies(
            policies if policies is not None else self.DEFAULT_POLICIES
        )

    @staticmethod
    def _validate_policies(
        policies: Mapping[str, Mapping[str, float]],
    ) -> dict[str, dict[str, float]]:
        if not policies:
            raise ValueError("At least one context policy is required")
        validated: dict[str, dict[str, float]] = {}
        for context, policy in policies.items():
            if not isinstance(context, str) or not context.strip():
                raise ValueError("Policy context names must be non-empty strings")
            if not isinstance(policy, Mapping):
                raise ValueError(f"Policy for {context!r} must be a mapping")
            try:
                rewrite_at = float(policy["rewrite_at"])
                yank_at = float(policy["yank_at"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    f"Policy for {context!r} requires numeric rewrite_at and yank_at"
                ) from exc
            if not math.isfinite(rewrite_at) or not math.isfinite(yank_at):
                raise ValueError(f"Thresholds for {context!r} must be finite")
            if not 0.0 <= rewrite_at < yank_at <= 1.0:
                raise ValueError(
                    f"Policy for {context!r} must satisfy "
                    "0 <= rewrite_at < yank_at <= 1"
                )
            validated[context] = {"rewrite_at": rewrite_at, "yank_at": yank_at}
        return validated

    @staticmethod
    def _score(value: Any, label: str) -> float:
        if isinstance(value, bool):
            raise TypeError(f"{label} must be a number, not bool")
        try:
            score = float(value)
        except (TypeError, ValueError) as exc:
            raise TypeError(f"{label} must be a number") from exc
        if not math.isfinite(score) or not 0.0 <= score <= 1.0:
            raise ValueError(f"{label} must be finite and between 0 and 1")
        return score

    def review(
        self,
        original_output: str,
        context: str,
        risk_score: float = 0.0,
    ) -> dict[str, Any]:
        if not isinstance(original_output, str):
            raise TypeError("original_output must be a string")
        if not isinstance(context, str) or context not in self.policies:
            raise ValueError(
                f"Unsupported context {context!r}; expected one of {sorted(self.policies)}"
            )
        score = self._score(risk_score, "risk_score")
        policy = self.policies[context]

        if score >= policy["yank_at"]:
            action = "yank"
        elif score >= policy["rewrite_at"]:
            action = "rewrite"
        else:
            action = "pass"

        final_output = original_output
        outcome = "passed"
        rewrite_error: str | None = None

        if action == "rewrite":
            outcome = "safe_replacement"
            if self.rewriter is not None and self.rewrite_risk_evaluator is not None:
                try:
                    candidate = self.rewriter(original_output, context)
                    if not isinstance(candidate, str) or not candidate.strip():
                        raise ValueError("Rewriter returned empty or non-string output")
                    candidate_score = self._score(
                        self.rewrite_risk_evaluator(candidate, context),
                        "rewrite_risk_score",
                    )
                    if candidate_score < policy["rewrite_at"]:
                        final_output = candidate
                        outcome = "rewritten"
                except Exception as exc:
                    rewrite_error = type(exc).__name__
            # Without independent evaluation, do not release rewrite output.
            if outcome != "rewritten":
                final_output = self._safe_replacement(context)

        elif action == "yank":
            final_output = self._safe_replacement(context)
            outcome = "withheld"

        verdict: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "risk_score": round(score, 6),
            "action": action,
            "context": context,
            "judge_model": self.model,
            "input_sha3_512": self._sha3(original_output),
            "output_sha3_512": self._sha3(final_output),
        }
        input_hmac = self._keyed_digest(original_output)
        if input_hmac is not None:
            verdict["input_hmac_sha3_512"] = input_hmac

        result: dict[str, Any] = {
            "final_output": final_output,
            "verdict": verdict,
            "outcome": outcome,
            "judge_model": self.model,
        }
        if rewrite_error is not None:
            result["rewrite_error"] = rewrite_error

        try:
            self._log_to_repmhl(verdict, final_output)
        except Exception as exc:
            if self.fail_closed_on_log_error:
                raise RuntimeError("Audit logging failed; response withheld") from exc
            result["audit_log_error"] = type(exc).__name__
        return result

    @staticmethod
    def _sha3(text: str) -> str:
        return hashlib.sha3_512(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _safe_replacement(context: str) -> str:
        if context in {"medical", "legal", "financial"}:
            return "I’m sorry, I cannot provide that information safely."
        return "Let’s try a different approach."

    def _keyed_digest(self, text: str) -> str | None:
        if self.audit_hmac_key is None:
            return None
        return hmac.new(
            self.audit_hmac_key, text.encode("utf-8"), hashlib.sha3_512
        ).hexdigest()

    def _log_to_repmhl(
        self, verdict: dict[str, Any], final_output: str
    ) -> None:
        if self.repmhl is None:
            raise RuntimeError("Required REPMHL audit sink is not configured")
        logger = getattr(self.repmhl, "log", None)
        if not callable(logger):
            raise TypeError("REPMHL sink must implement log(dict)")
        event: dict[str, Any] = {
            "event": "HEAVY_JUDGE_VERDICT",
            "verdict": verdict,
            "output_sha3_512": self._sha3(final_output),
        }
        output_hmac = self._keyed_digest(final_output)
        if output_hmac is not None:
            event["output_hmac_sha3_512"] = output_hmac
        logger(event)
