#!/usr/bin/env python3
"""DevAssist420 Heavy Judge: deterministic policy gate for model proposals.

This module does not itself infer risk or call a provider. The caller must supply
a risk score from an explicitly selected evaluator. Provider/model output is
untrusted input. Gate.One remains the independent authorization boundary.
"""
from __future__ import annotations

import hashlib
import hmac
import math
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any


class HeavyJudge:
    """Apply context-specific thresholds and emit a REPMHL-compatible event.

    The audit sink contract is intentionally repmhl.log(dict). If a sink is
    configured and fails, the response is withheld when fail-closed mode is on.
    """

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
            validated[context] = {
                "rewrite_at": rewrite_at,
                "yank_at": yank_at,
            }
        return validated

    def review(
        self,
        original_output: str,
        context: str,
        risk_score: float = 0.0,
    ) -> dict[str, Any]:
        self._validate_review_input(original_output, context, risk_score)
        score = float(risk_score)
        verdict = self._generate_verdict(original_output, context, score)
        action = verdict["action"]
        rewrite_error: str | None = None

        if action == "pass":
            final_output = original_output
            outcome = "passed"
        elif action == "rewrite" and self.rewriter is not None:
            try:
                candidate = self.rewriter(original_output, context)
                if not isinstance(candidate, str) or not candidate.strip():
                    raise ValueError("Rewriter returned empty or non-string output")
                final_output = candidate
                outcome = "rewritten"
            except Exception as exc:
                final_output = self._safe_replacement(context)
                outcome = "safe_replacement"
                rewrite_error = type(exc).__name__
        else:
            # YANK, or REWRITE without an approved rewriter: never leak original.
            final_output = self._safe_replacement(context)
            outcome = "safe_replacement"

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

    def _validate_review_input(
        self, original_output: str, context: str, risk_score: float
    ) -> None:
        if not isinstance(original_output, str):
            raise TypeError("original_output must be a string")
        if not isinstance(context, str) or context not in self.policies:
            raise ValueError(
                f"Unsupported context {context!r}; expected one of {sorted(self.policies)}"
            )
        if isinstance(risk_score, bool):
            raise TypeError("risk_score must be a number, not bool")
        try:
            score = float(risk_score)
        except (TypeError, ValueError) as exc:
            raise TypeError("risk_score must be a number") from exc
        if not math.isfinite(score) or not 0.0 <= score <= 1.0:
            raise ValueError("risk_score must be finite and between 0 and 1")

    def _generate_verdict(
        self, original_output: str, context: str, risk_score: float
    ) -> dict[str, Any]:
        policy = self.policies[context]
        if risk_score >= policy["yank_at"]:
            action = "yank"
        elif risk_score >= policy["rewrite_at"]:
            action = "rewrite"
        else:
            action = "pass"
        verdict: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "risk_score": round(risk_score, 3),
            "action": action,
            "context": context,
        }
        input_hmac = self._keyed_digest(original_output)
        if input_hmac is not None:
            verdict["input_hmac_sha3_512"] = input_hmac
        return verdict

    @staticmethod
    def _safe_replacement(context: str) -> str:
        if context in {"medical", "legal", "financial"}:
            return "I’m sorry, I cannot provide that information safely."
        return "Let’s try a different approach."

    def _keyed_digest(self, text: str) -> str | None:
        if self.audit_hmac_key is None:
            return None
        return hmac.new(
            self.audit_hmac_key,
            text.encode("utf-8"),
            hashlib.sha3_512,
        ).hexdigest()

    def _log_to_repmhl(
        self, verdict: dict[str, Any], final_output: str
    ) -> None:
        if self.repmhl is None:
            return
        logger = getattr(self.repmhl, "log", None)
        if not callable(logger):
            raise TypeError("REPMHL sink must implement log(dict)")
        event = {
            "event": "HEAVY_JUDGE_VERDICT",
            "verdict": verdict,
            "output_hmac_sha3_512": self._keyed_digest(final_output),
        }
        logger(event)
