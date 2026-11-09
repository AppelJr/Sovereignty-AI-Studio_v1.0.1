"""Compose an advisory model judge with the deterministic HeavyJudge gate.

The model backend may escalate, but cannot downgrade the behavioral gate or
itself grant authority. The outer Gate and release evidence boundary remain
separate. Verdicts bind task, policy, judge identity, and exact candidate digest.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import os
from typing import Any, Callable, Literal, Mapping, Protocol, Sequence

Action = Literal["PASS", "REWRITE", "YANK", "COUNCIL"]
ACTIONS = frozenset({"PASS", "REWRITE", "YANK", "COUNCIL"})
SEVERITY = {"PASS": 0, "REWRITE": 1, "COUNCIL": 2, "YANK": 3}

class JudgeCompositionError(RuntimeError):
    """Base exception for the fail-closed composed judge."""

class BackendConfigurationError(JudgeCompositionError):
    """Judge backend configuration is missing or invalid."""

class BackendUnavailable(JudgeCompositionError):
    """Judge backend cannot provide a valid review."""

class EvidenceUnavailable(JudgeCompositionError):
    """Required judge evidence could not be written."""

class ModelReviewBackend(Protocol):
    model_id: str
    def evaluate(self, candidate: str, context: str) -> Mapping[str, Any]: ...

BackendBuilder = Callable[[str], ModelReviewBackend]
EvidenceSink = Callable[[dict[str, Any]], Any]

@dataclass(frozen=True, slots=True)
class ModelReview:
    model_id: str
    action: Action
    reason: str


def build_judge(backend_builder: BackendBuilder, *, environ: Mapping[str, str] | None = None) -> ModelReviewBackend:
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
    """Independent judge composition; most restrictive advisory/gate result wins."""
    def __init__(self, *, backend: ModelReviewBackend, behavioral_judge: Any,
                 evidence_sink: EvidenceSink, judge_id: str | None = None,
                 provider_ids: Sequence[str] | None = None) -> None:
        if not callable(getattr(backend, "evaluate", None)):
            raise TypeError("a bound model review backend is mandatory")
        if not callable(getattr(behavioral_judge, "review", None)):
            raise TypeError("behavioral_judge.review is mandatory")
        if not callable(evidence_sink):
            raise TypeError("mandatory evidence_sink is required")
        backend_id = str(getattr(backend, "model_id", "")).strip()
        if not backend_id:
            raise TypeError("judge backend model_id is required")
        self.backend = backend
        self.behavioral_judge = behavioral_judge
        self.evidence_sink = evidence_sink
        self.judge_id = str(judge_id or backend_id).strip()
        if not self.judge_id:
            raise ValueError("judge_id is required")
        self._provider_ids = {str(item).strip().casefold() for item in (provider_ids or ()) if str(item).strip()}
        self.assert_independent(provider_ids or ())

    def assert_independent(self, provider_ids: Sequence[str]) -> None:
        """Reject backend or configured judge identity overlap with generating lanes."""
        identities = {str(item).strip().casefold() for item in provider_ids if str(item).strip()}
        identities |= self._provider_ids
        identities |= {str(getattr(self.backend, "model_id", "")).strip().casefold()}
        if self.judge_id.casefold() in identities:
            raise ValueError("judge identity must be independent of the provider identities")

    @staticmethod
    def _action(value: Any) -> Action:
        action = str(value).upper()
        if action not in ACTIONS:
            raise ValueError("unsupported judge action")
        return action  # type: ignore[return-value]

    def _record(self, event: dict[str, Any]) -> None:
        try:
            self.evidence_sink(event)
        except Exception as exc:
            raise EvidenceUnavailable("composed judge evidence append failed") from exc

    def review(self, original_output: str, context: str = "general", force_judge: bool = False,
               token_manager: Any = None, *, council_result: Mapping[str, Any] | None = None,
               task_id: str | None = None, policy_hash: str | None = None,
               candidate_hash: str | None = None, judge_id: str | None = None) -> dict[str, Any]:
        del force_judge, token_manager
        if not isinstance(original_output, str) or not original_output.strip():
            raise ValueError("candidate output must be non-empty")
        if not task_id or not policy_hash:
            raise ValueError("task_id and policy_hash are required for an auditable judge verdict")
        digest = "sha3-512:" + hashlib.sha3_512(original_output.encode("utf-8")).hexdigest()
        if candidate_hash != digest:
            raise ValueError("candidate hash must match the exact output being judged")
        selected_judge_id = str(judge_id or self.judge_id).strip()
        if selected_judge_id != self.judge_id:
            raise ValueError("requested judge identity does not match the configured independent judge")
        self.assert_independent(())
        timestamp = datetime.now(timezone.utc).isoformat()
        backend_id = str(getattr(self.backend, "model_id", "unknown"))
        try:
            raw = self.backend.evaluate(original_output, str(context))
            if not isinstance(raw, Mapping):
                raise BackendUnavailable("model review must be a mapping")
            returned_id = str(raw.get("model_id", backend_id))
            if returned_id != backend_id:
                raise BackendUnavailable("judge backend identity changed during review")
            model_action = self._action(raw.get("action"))
            model_reason = str(raw.get("reason", "model review"))
            memory_loaded = raw.get("memory_loaded")
            network_accessed = raw.get("network_accessed")
            if not isinstance(memory_loaded, bool) or not isinstance(network_accessed, bool):
                raise BackendUnavailable("backend must report boolean memory_loaded and network_accessed")
        except Exception as exc:
            self._record({"who":"ComposedHeavyJudge","what":"JUDGE_BACKEND_FAILURE","when":timestamp,
                          "where":"sovereign_core.judge_composition","why":"judge backend unavailable or malformed",
                          "how":"fail closed","authorization":"not_authorized_by_judge",
                          "memory_loaded":"UNKNOWN","network_accessed":"UNKNOWN","files_changed":[],
                          "result":"YANK","task_id":task_id,"policy_hash":policy_hash,
                          "candidate_hash":digest,"judge_id":self.judge_id,"error_type":type(exc).__name__})
            verdict = {"timestamp":timestamp,"risk_score":1.0,"action":"YANK","output_hash":digest,
                       "candidate_hash":digest,"signature":None,"context":str(context),"judge_model":backend_id,
                       "judge_id":self.judge_id,"task_id":task_id,"policy_hash":policy_hash,
                       "reason":"judge backend unavailable"}
            return {"final_output":None,"verdict":verdict,"model_review":{"action":"YANK"}}

        try:
            behavioral = self.behavioral_judge.review(original_output=original_output, context=str(context),
                                                       force_judge=True, council_result=council_result)
            if not isinstance(behavioral, Mapping) or not isinstance(behavioral.get("verdict"), Mapping):
                raise ValueError("behavioral verdict missing")
            behavioral_verdict = behavioral["verdict"]
            behavioral_action = self._action(behavioral_verdict.get("action"))
            risk_score = float(behavioral_verdict.get("risk_score", 1.0))
            if not 0 <= risk_score <= 1:
                raise ValueError("risk score outside [0, 1]")
        except Exception as exc:
            behavioral_action, risk_score = "YANK", 1.0
            behavioral_verdict = {"action":"YANK","risk_score":1.0,"reason":type(exc).__name__}
        action = max((model_action, behavioral_action), key=lambda item: SEVERITY[item])
        final_output = behavioral.get("final_output") if action == "PASS" else None
        if action == "PASS" and final_output != original_output:
            action, final_output = "YANK", None
        verdict = {"timestamp":timestamp,"risk_score":risk_score,"action":action,
                   "output_hash":digest,"candidate_hash":digest,"signature":None,"context":str(context),
                   "judge_model":backend_id,"judge_id":self.judge_id,"task_id":task_id,
                   "policy_hash":policy_hash,"reason":f"model={model_action}:{model_reason}; behavioral={behavioral_action}"}
        self._record({"who":"ComposedHeavyJudge","what":"COMPOSED_JUDGE_VERDICT","when":timestamp,
                      "where":"sovereign_core.judge_composition","why":verdict["reason"],
                      "how":"model advisory + deterministic behavioral gate; restrictive action wins",
                      "authorization":"Gate authorization remains external","memory_loaded":memory_loaded,
                      "network_accessed":network_accessed,"files_changed":[],"result":action,
                      "output_hash":digest,"candidate_hash":digest,"judge_id":self.judge_id,
                      "task_id":task_id,"policy_hash":policy_hash})
        return {"final_output":final_output if action == "PASS" else None,"verdict":verdict,
                "model_review":asdict(ModelReview(backend_id,model_action,model_reason)),
                "behavioral_verdict":dict(behavioral_verdict),"memory_loaded":memory_loaded,
                "network_accessed":network_accessed}


def compose_judge(*, backend_builder: BackendBuilder, behavioral_judge: Any, evidence_sink: EvidenceSink,
                  environ: Mapping[str, str] | None = None, judge_id: str | None = None,
                  provider_ids: Sequence[str] | None = None) -> ComposedHeavyJudge:
    backend = build_judge(backend_builder, environ=environ)
    return ComposedHeavyJudge(backend=backend,behavioral_judge=behavioral_judge,evidence_sink=evidence_sink,
                              judge_id=judge_id,provider_ids=provider_ids)


__all__ = ["Action","ACTIONS","BackendConfigurationError","BackendUnavailable","ComposedHeavyJudge",
           "EvidenceUnavailable","JudgeCompositionError","ModelReview","build_judge","compose_judge"]
