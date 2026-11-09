#!/usr/bin/env python3
"""Gate-bound smart provider router with mandatory composed Heavy Judge."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any, Callable, Mapping, Sequence

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
    """Candidate was withheld pending separate review."""

class EvidenceWriteError(RuntimeError):
    """Mandatory evidence could not be persisted."""

class SmartProviderRouter:
    """Coordinate provider, Council, and independent Judge; never grant authority."""
    def __init__(self, token_manager: Any, *, council_adapter: Callable[[dict[str, Any]], Mapping[str, Any]],
                 judge: ComposedHeavyJudge, provider_ids: Sequence[str] = ()) -> None:
        if not callable(council_adapter):
            raise TypeError("a real three-lane council_adapter is mandatory")
        if not isinstance(judge, ComposedHeavyJudge):
            raise TypeError("a configured ComposedHeavyJudge is mandatory; no legacy bypass")
        self.token_manager = token_manager
        self.config = token_manager.config
        self.judge = judge
        self.council_adapter = council_adapter
        self.provider_ids = tuple(provider_ids)
        self.priority_rules = {
            "medical":["anthropic","xai","openai"], "education":["anthropic","xai","openai"],
            "general":["xai","anthropic","openai"], "coding":["openai","anthropic","xai"],
            "legal":["anthropic","openai","xai"], "financial":["openai","anthropic","xai"],
            "security":["openai","xai","anthropic"],
        }

    def _get_provider_capacity(self, provider: str) -> int:
        state = self.token_manager.states.get(provider)
        if state:
            return max(0, int(state.max_tokens) - int(state.token_count))
        cfg = self.config.get("providers", {}).get(provider)
        return int(cfg.get("base_max_tokens", 0)) if isinstance(cfg, Mapping) else 0

    def route_request(self, text: str, context: str = "general", prefer_cheap: bool = True) -> RoutingDecision:
        del text, prefer_cheap
        for provider in self.priority_rules.get(context, self.priority_rules["general"]):
            capacity = self._get_provider_capacity(provider)
            if capacity > 512:
                return RoutingDecision(provider, f"Best available for context={context}", capacity,
                                       COST_TIERS.get(provider, 2.0))
        raise RuntimeError("no provider has sufficient configured capacity; refusing fallback")

    def consume_with_routing(self, tokens: int, text: str, *, context: str,
                             authorization_proof: str, verification_key: bytes, task_id: str,
                             owner_id: str, required_scope: tuple[str, ...],
                             evidence_sink: Callable[[dict[str, Any]], Any],
                             prefer_cheap: bool = True, now: int | None = None) -> dict[str, Any]:
        if not callable(evidence_sink):
            raise TypeError("evidence_sink is mandatory")
        execution: dict[str, Any] = {}

        def route_and_judge(claims: Any) -> Mapping[str, Any]:
            decision = self.route_request(text, context, prefer_cheap)
            self.judge.assert_independent((*self.provider_ids, decision.provider))
            if decision.provider not in self.token_manager.states:
                self.token_manager.start_session(decision.provider)
            model_result = self.token_manager.consume_tokens(decision.provider, tokens)
            if not isinstance(model_result, Mapping):
                raise RuntimeError("provider returned invalid result")
            candidate = model_result.get("output")
            if not isinstance(candidate, str) or not candidate.strip():
                raise RuntimeError("provider returned no candidate output; refusing placeholder")
            council = self.council_adapter({"task_id":task_id,"owner_id":owner_id,"request":text,
                                            "candidate":candidate,"context":context,"route":asdict(decision)})
            if not isinstance(council, Mapping):
                raise RuntimeError("Council returned invalid result")
            votes = council.get("votes")
            if not isinstance(votes, Mapping) or not REQUIRED_COUNCIL_LANES.issubset(votes):
                raise RuntimeError("Council must provide all three lanes: Grok, GPT/Codex and Claude votes")
            if any(str(votes[lane]).upper() not in VALID_COUNCIL_ACTIONS for lane in REQUIRED_COUNCIL_LANES):
                raise RuntimeError("Council contains unsupported lane action")
            council_action = str(council.get("action", "")).upper()
            if council_action not in VALID_COUNCIL_ACTIONS:
                raise RuntimeError("Council aggregate action is missing or unsupported")
            candidate_hash = "sha3-512:" + hashlib.sha3_512(candidate.encode("utf-8")).hexdigest()
            judged = self.judge.review(original_output=candidate, context=context, force_judge=True,
                                       council_result=council, task_id=task_id,
                                       policy_hash=claims.policy_hash, candidate_hash=candidate_hash)
            if not isinstance(judged, Mapping) or not isinstance(judged.get("verdict"), Mapping):
                raise RuntimeError("ComposedHeavyJudge returned invalid result")
            verdict = dict(judged["verdict"])
            if verdict.get("task_id") != task_id or verdict.get("candidate_hash") != candidate_hash:
                raise RuntimeError("Heavy Judge verdict task or candidate binding mismatch")
            if verdict.get("policy_hash") != claims.policy_hash:
                raise RuntimeError("Heavy Judge verdict policy binding mismatch")
            if verdict.get("judge_id") != self.judge.judge_id:
                raise RuntimeError("Heavy Judge identity binding mismatch")
            action = str(verdict.get("action", "")).upper()
            if action != "PASS" or council_action != "PASS":
                event = {"who":"SmartProviderRouter","what":"ESCROW_PENDING_REVIEW",
                         "when":datetime.now(timezone.utc).isoformat(),"where":"Sovereignty-AI-Studio_v1.0.1",
                         "why":"Council or independent Heavy Judge did not return PASS",
                         "how":"provider -> Council -> independent Judge","authorization":claims.proof_id,
                         "memory_loaded":False,"network_accessed":True,"files_changed":[],
                         "result":action if action != "PASS" else council_action,"task_id":task_id,
                         "candidate_hash":candidate_hash,"judge_verdict":verdict,"council":dict(council)}
                try:
                    evidence_sink(event)
                except Exception as exc:
                    raise EvidenceWriteError("escrow evidence append failed") from exc
                execution.update({"status":"ESCROW_PENDING_REVIEW","action":action,
                                  "council":dict(council),"judge_verdict":verdict})
                raise EscrowPending(f"{action or council_action or 'INVALID'} requires review")
            output = judged.get("final_output")
            if output != candidate:
                raise RuntimeError("Heavy Judge PASS did not preserve the exact candidate")
            output_hash = candidate_hash
            execution.update({"status":"PASS","output":output,"output_hash":output_hash,
                              "routed_to":decision.provider,"routing_reason":decision.reason,
                              "council":dict(council),"judge_verdict":verdict})
            return {"status":"PASS","output":output,"output_hash":output_hash,"judge_verdict":verdict}

        try:
            receipt = run_dual_gated(proof=authorization_proof, verification_key=verification_key,
                                     task_id=task_id, owner_id=owner_id, required_scope=required_scope,
                                     route_and_judge=route_and_judge, evidence_sink=evidence_sink,
                                     now=now, memory_loaded=False, network_accessed=True)
        except EscrowPending:
            return execution
        return {**execution,"status":receipt.release_status,"output":receipt.output,
                "output_hash":receipt.output_hash,"authorization_proof_id":receipt.authorization_proof_id,
                "policy_hash":receipt.authorization_policy_hash,"evidence_event_hash":receipt.evidence_event_hash,
                "used_judge":True}

__all__ = ["EscrowPending","EvidenceWriteError","RoutingDecision","SmartProviderRouter"]
