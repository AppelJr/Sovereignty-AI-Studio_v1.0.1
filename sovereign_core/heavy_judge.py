"""Heavy Judge: deterministic quality/risk gate; no simulated provider votes.

Provider calls and Council aggregation are separate injected boundaries. This
module never fabricates votes, signatures, model output, or audit success.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any, Callable, Literal, Mapping

Action = Literal["PASS", "REWRITE", "YANK"]
Signer = Callable[[bytes], str]


@dataclass(frozen=True, slots=True)
class JudgeVerdict:
    timestamp: str
    risk_score: float
    action: Action
    output_hash: str
    signature: str | None
    context: str
    judge_model: str
    reason: str


class HeavyJudge:
    """Final risk gate over a candidate already produced by provider lanes."""

    DEFAULT_THRESHOLDS = {"medical": 0.35, "education": 0.40, "general": 0.65,
                          "legal": 0.35, "financial": 0.40, "security": 0.30}

    def __init__(
        self,
        model_name: str = "Sovereignty-HeavyJudge",
        *,
        thresholds: Mapping[str, float] | None = None,
        signer: Signer | None = None,
        evidence_sink: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self.model_name = model_name
        self.thresholds = dict(self.DEFAULT_THRESHOLDS)
        if thresholds:
            for key, value in thresholds.items():
                if not isinstance(value, (int, float)) or not 0 <= float(value) <= 1:
                    raise ValueError(f"invalid threshold for {key}")
                self.thresholds[str(key).lower()] = float(value)
        self.signer = signer
        self.evidence_sink = evidence_sink

    @staticmethod
    def _risk(text: str, context: str) -> tuple[float, list[str]]:
        value = 0.0
        reasons: list[str] = []
        lower = text.lower()
        signals = {
            "unsupported certainty": (("guaranteed", "100% certain", "proven beyond doubt"), 0.12),
            "uncertainty disclosure": (("i guess", "not sure", "possibly", "might be"), 0.04),
            "medical action language": (("diagnose", "take this dose", "stop medication", "cure"), 0.32),
            "credential or secret exposure": (("private key", "api key", "password=", "bearer "), 0.45),
            "destructive operation": (("rm -rf", "drop database", "delete all"), 0.40),
        }
        for label, (phrases, weight) in signals.items():
            if any(term in lower for term in phrases):
                value += weight
                reasons.append(label)
        if context in {"medical", "legal", "financial", "security"}:
            value += 0.12
            reasons.append(f"high-impact context: {context}")
        return min(value, 1.0), reasons

    def review(
        self,
        original_output: str,
        context: str = "general",
        force_judge: bool = False,
        token_manager: Any = None,
        *,
        council_result: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(original_output, str) or not original_output.strip():
            raise ValueError("candidate output must be a non-empty string")
        context_key = str(context).lower()
        score, reasons = self._risk(original_output, context_key)
        threshold = self.thresholds.get(context_key, self.thresholds["general"])

        council_action = None
        if council_result is not None:
            council_action = str(council_result.get("action", "")).upper()
            if council_action not in {"PASS", "REWRITE", "YANK"}:
                raise ValueError("Council action must be PASS, REWRITE, or YANK")

        critical_signal = any(item in reasons for item in ("credential or secret exposure", "destructive operation"))
        if council_action == "YANK" or critical_signal or score >= min(0.90, threshold + 0.40):
            action: Action = "YANK"
        elif council_action == "REWRITE" or score > threshold:
            action = "REWRITE"
        else:
            action = "PASS"

        digest = hashlib.sha3_512(original_output.encode("utf-8")).digest()
        signature = self.signer(digest) if self.signer else None
        verdict = JudgeVerdict(
            timestamp=datetime.now(timezone.utc).isoformat(),
            risk_score=round(score, 4),
            action=action,
            output_hash="sha3-512:" + digest.hex(),
            signature=signature,
            context=context_key,
            judge_model=self.model_name,
            reason="; ".join(reasons) if reasons else "no configured risk signal detected",
        )
        result = {
            "final_output": original_output if action == "PASS" else None,
            "verdict": asdict(verdict),
            "triggered_council": council_result is not None,
            "council_result": dict(council_result) if council_result is not None else None,
        }
        if self.evidence_sink is not None:
            self.evidence_sink({
                "event": "HEAVY_JUDGE_VERDICT",
                "action": action,
                "context": context_key,
                "risk_score": verdict.risk_score,
                "output_hash": verdict.output_hash,
                "signature_present": signature is not None,
                "reason": verdict.reason,
                "timestamp": verdict.timestamp,
            })
        return result
