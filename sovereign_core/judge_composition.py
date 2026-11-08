"""Compose an advisory model judge with the deterministic HeavyJudge gate.

The model backend may escalate a candidate, but can never downgrade the
behavioral judge's action or authorize release. Backend construction is lazy:
missing configuration fails at construction time, never at import time.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import os
from typing import Any, Callable, Literal, Mapping, Protocol

Action = Literal["PASS", "REWRITE", "YANK", "COUNCIL"]
ACTIONS = frozenset({"PASS", "REWRITE", "YANK", "COUNCIL"})
SEVERITY = {"PASS": 0, "REWRITE": 1, "COUNCIL": 2, "YANK": 3}


class JudgeCompositionError(RuntimeError):
    """Base error for a fail-closed composed judge."""


class BackendConfigurationError(JudgeCompositionError):
    """The judge backend cannot be safely constructed."""


class BackendUnavailable(JudgeCompositionError):
    """The configured judge backend failed or is unbound."""


class EvidenceUnavailable(JudgeCompositionError):
    """Mandatory composed-judge evidence could not be persisted."""


class ModelReviewBackend(Protocol):
    model_id: str

    def evaluate(self, candidate: str, context: str) -> Mapping[str, Any]:
        """Return an advisory action: PASS, REWRITE, YANK, or COUNCIL."""


BackendBuilder = Callable[[str], ModelReviewBackend]
EvidenceSink = Callable[[dict[str, Any]], Any]


@dataclass(frozen=True, slots=True)
class ModelReview:
    model_id: str
    action: Action
    reason: str


@dataclass(frozen=True, slots=True)
class ComposedReview:
    model_review: ModelReview
    behavioral_verdict: Mapping[str, Any]
    action: Action
    output_hash: str
    final_output: str | None


def build_judge(
    backend_builder: BackendBuilder,
    *,
    environ: Mapping[str, str] | None = None,
) -> ModelReviewBackend:
    """Build the model-review backend on demand; never read config at import.

    The caller supplies the HFChatModel-compatible adapter factory. The adapter
    must expose evaluate(candidate, context) and model_id. LOCAL_LLM is rejected
    as an override so this path cannot silently select an alternate local model.
    """
    if not callable(backend_builder):
        raise BackendConfigurationError("judge backend builder is unbound")
    env = os.environ if environ is None else environ
    model_name = str(env.get("HEAVYJUDGE_MODEL", "")).strip()
    if not model_name:
        raise BackendConfigurationError("HEAVYJUDGE_MODEL is required")
    if str(env.get("LOCAL_LLM", "")).strip().lower() in {"1", "true", "yes", "on"}:
        raise BackendConfigurationError("LOCAL_LLM override is prohibited")
    try:
        backend = backend_builder(model_name)
    except Exception as exc:
        raise BackendUnavailable("judge backend construction failed") from exc
    if not callable(getattr(backend, "evaluate", None)):
        raise BackendUnavailable("backend must implement evaluate(candidate, context)")
    model_id = getattr(backend, "model_id", model_name)
    if not isinstance(model_id, str) or not model_id.strip():
        raise BackendUnavailable("backend model_id is missing")
    return backend


class ComposedHeavyJudge:
    """HeavyJudge-compatible composition: model advisory + behavioral gate.

    PASS is possible only when both layers PASS. Any disagreement resolves to
    the more restrictive action. COUNCIL is a hold state, never a release state.
    """

    def __init__(
        self,
        *,
        backend: ModelReviewBackend,
        behavioral_judge: Any,
        evidence_sink: EvidenceSink,
    ) -> None:
        if not callable(getattr(backend, "evaluate", None)):
            raise TypeError("a bound model review backend is mandatory")
        if not callable(getattr(behavioral_judge, "review", None)):
            raise TypeError("behavioral_judge.review is mandatory")
        if not callable(evidence_sink):
            raise TypeError("mandatory evidence_sink is required")
        self.backend = backend
        self.behavioral_judge = behavioral_judge
        self.evidence_sink = evidence_sink

    @staticmethod
    def _action(value: Any) -> Action:
        action = str(value).upper()
        if action not in ACTIONS:
            raise ValueError("unsupported model or behavioral action")
        return action  # type: ignore[return-value]

    def _record(self, event: dict[str, Any]) -> None:
        try:
            self.evidence_sink(event)
        except Exception as exc:
            raise EvidenceUnavailable("composed judge evidence append failed") from exc

    def review(
        self,
        original_output: str,
        context: str = "general",
        force_judge: bool = False,
        token_manager: Any = None,
        *,
        council_result: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        del force_judge, token_manager
        if not isinstance(original_output, str) or not original_output.strip():
            raise ValueError("candidate output must be non-empty")
        digest = "sha3-512:" + hashlib.sha3_512(
            original_output.encode("utf-8")
        ).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()
        model_id = str(getattr(self.backend, "model_id", "unknown"))

        try:
            raw_model_review = self.backend.evaluate(original_output, str(context))
            if not isinstance(raw_model_review, Mapping):
                raise BackendUnavailable("model review must be a mapping")
            model_action = self._action(raw_model_review.get("action"))
            model_reason = str(raw_model_review.get("reason", "model review"))
            model_id = str(raw_model_review.get("model_id", model_id))
            memory_loaded = raw_model_review.get("memory_loaded")
            network_accessed = raw_model_review.get("network_accessed")
            if not isinstance(memory_loaded, bool) or not isinstance(network_accessed, bool):
                raise BackendUnavailable(
                    "backend must report boolean memory_loaded and network_accessed"
                )
        except Exception as exc:
            self._record({
                "who": "ComposedHeavyJudge",
                "what": "JUDGE_BACKEND_FAILURE",
                "when": timestamp,
                "where": "sovereign_core.judge_composition",
                "why": "model review unavailable or malformed",
                "how": "model backend failure defaults to YANK",
                "authorization": "not_authorized_by_judge",
                "memory_loaded": "UNKNOWN",
                "network_accessed": "UNKNOWN",
                "files_changed": [],
                "result": "YANK",
                "output_hash": digest,
                "model_id": model_id,
                "error_type": type(exc).__name__,
            })
            return {
                "final_output": None,
                "verdict": {
                    "timestamp": timestamp, "risk_score": 1.0, "action": "YANK",
                    "output_hash": digest, "signature": None, "context": str(context),
                    "judge_model": model_id, "reason": "model backend failure",
                },
                "model_review": {"action": "YANK", "reason": "model backend failure"},
            }

        try:
            behavioral = self.behavioral_judge.review(
                original_output=original_output,
                context=str(context),
                force_judge=True,
                council_result=council_result,
            )
            if not isinstance(behavioral, Mapping):
                raise ValueError("behavioral judge result must be a mapping")
            behavioral_verdict = behavioral.get("verdict")
            if not isinstance(behavioral_verdict, Mapping):
                raise ValueError("behavioral judge verdict missing")
            behavioral_action = self._action(behavioral_verdict.get("action"))
            risk_score = float(behavioral_verdict.get("risk_score", 1.0))
            if not 0.0 <= risk_score <= 1.0:
                raise ValueError("behavioral risk_score outside [0, 1]")
        except Exception as exc:
            behavioral_action = "YANK"
            risk_score = 1.0
            behavioral_verdict = {
                "timestamp": timestamp, "risk_score": 1.0, "action": "YANK",
                "output_hash": digest, "signature": None, "context": str(context),
                "judge_model": "behavioral-judge", "reason": type(exc).__name__,
            }

        action = max(
            (model_action, behavioral_action),
            key=lambda item: SEVERITY[item],
        )
        final_output = (
            behavioral.get("final_output")
            if action == "PASS" and isinstance(behavioral, Mapping)
            else None
        )
        if action == "PASS" and (
            not isinstance(final_output, str) or final_output != original_output
        ):
            action = "YANK"
            final_output = None

        verdict = {
            **dict(behavioral_verdict),
            "timestamp": timestamp,
            "risk_score": risk_score,
            "action": action,
            "output_hash": digest,
            "judge_model": model_id,
            "reason": (
                f"model={model_action}:{model_reason}; "
                f"behavioral={behavioral_action}"
            ),
        }
        self._record({
            "who": "ComposedHeavyJudge",
            "what": "COMPOSED_JUDGE_VERDICT",
            "when": timestamp,
            "where": "sovereign_core.judge_composition",
            "why": verdict["reason"],
            "how": "model advisory + deterministic behavioral gate; restrictive action wins",
            "authorization": "Gate authorization remains external",
            "memory_loaded": memory_loaded,
            "network_accessed": network_accessed,
            "files_changed": [],
            "result": action,
            "model_id": model_id,
            "model_action": model_action,
            "behavioral_action": behavioral_action,
            "output_hash": digest,
        })
        return {
            "final_output": final_output if action == "PASS" else None,
            "verdict": verdict,
            "model_review": asdict(ModelReview(
                model_id=model_id, action=model_action, reason=model_reason
            )),
            "behavioral_verdict": dict(behavioral_verdict),
        }


def compose_judge(
    *,
    backend_builder: BackendBuilder,
    behavioral_judge: Any,
    evidence_sink: EvidenceSink,
    environ: Mapping[str, str] | None = None,
) -> ComposedHeavyJudge:
    """Construct the one composed judge without import-time model loading."""
    backend = build_judge(backend_builder, environ=environ)
    return ComposedHeavyJudge(
        backend=backend,
        behavioral_judge=behavioral_judge,
        evidence_sink=evidence_sink,
    )
