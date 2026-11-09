#!/usr/bin/env python3
"""Gate-bound smart provider router with mandatory composed Heavy Judge."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Callable, Mapping

from backend.coordination.dual_gate_path import run_dual_gated
from sovereign_core.judge_composition import ComposedHeavyJudge

COST_TIERS = {"xai": 1.0, "anthropic": 1.8, "openai": 2.2}
COUNCIL_LANES = ("grok", "gpt_codex", "claude")
REQUIRED_COUNCIL_LANES = frozenset(COUNCIL_LANES)
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
    """Context-aware provider selection with mandatory dual-gate release."""

    def __init__(
        self,
        token_manager: Any,
        *,
        council_adapter: Callable[[dict[str, Any]], Mapping[str, Any]],
        judge: ComposedHeavyJudge,
        judge_provider_id: str,
    ) -> None:
        if not callable(council_adapter):
            raise TypeError("a real three-lane council_adapter is mandatory")
        if not isinstance(judge, ComposedHeavyJudge):
            raise TypeError("a configured ComposedHeavyJudge is mandatory; no legacy bypass")
        if not isinstance(judge_provider_id, str) or not judge_provider_id.strip():
            raise ValueError("an independent Judge provider identity is mandatory")
        backend_provider_id = getattr(judge.backend, "provider_id", None)
        if not isinstance(backend_provider_id, str) or backend_provider_id != judge_provider_id:
            raise ValueError("Judge provider identity must match the injected Judge backend")
        self.judge_provider_id = judge_provider_id.strip()
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

        def append_evidence(event: dict[str, Any]) -> Any:
            payload = dict(event)
            event_task = payload.get("task_id")
            if not isinstance(event_task, str) or not event_task:
                raise EvidenceWriteError("evidence event task_id is required")
            timestamp = payload.get("when")
            if not isinstance(timestamp, str) or not timestamp:
                timestamp = datetime.now(timezone.utc).isoformat()
            canonical = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            normalized = {
                **payload,
                "event": str(payload.get("what", "SMART_PROVIDER_ROUTER_EVENT")),
                "timestamp": timestamp,
                "event_hash": "sha256:" + hashlib.sha256(canonical).hexdigest(),
            }
            return evidence_sink(normalized)

        def route_and_judge(verified_claims: Any) -> Mapping[str, Any]:
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

            council_candidate = council.get("candidate")
            source_provider_id = council.get("source_provider_id")
            proposals = council.get("proposals")
            if not isinstance(council_candidate, str) or not council_candidate.strip():
                raise RuntimeError("Council did not provide a consolidated candidate")
            if not isinstance(proposals, Mapping) or not REQUIRED_COUNCIL_LANES.issubset(proposals):
                raise RuntimeError("Council must provide all three attributable lane proposals")
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
                proposal_provider_ids.append(provider_id.strip())
            if len({item.casefold() for item in proposal_provider_ids}) != len(REQUIRED_COUNCIL_LANES):
                raise RuntimeError("Council lanes must have distinct provider identities")
            for lane in COUNCIL_LANES:
                if str(votes[lane]).upper() != str(proposals[lane]["vote"]).upper():
                    raise RuntimeError(f"Council vote/proposal mismatch for {lane}")
            routed_proposal = next((item for item in proposals.values()
                                    if item["provider_id"].casefold() == decision.provider.casefold()), None)
            if routed_proposal is None or routed_proposal["candidate"] != candidate:
                raise RuntimeError("Council omitted or altered the routed provider proposal")
            if not isinstance(source_provider_id, str) or not source_provider_id.strip():
                raise RuntimeError("Council source-provider identity is missing")
            if source_provider_id != "council:aggregate":
                selected = next((item for item in proposals.values()
                                 if item["provider_id"].casefold() == source_provider_id.casefold()), None)
                if selected is None or selected["candidate"] != council_candidate:
                    raise RuntimeError("Council candidate/source binding mismatch")
            judged = self.judge.review(
                original_output=council_candidate,
                context=context,
                force_judge=True,
                council_result=council,
                task_id=task_id,
                policy_hash=verified_claims.policy_hash,
                judge_id=str(getattr(self.judge.backend, "model_id", "")),
                judge_provider_id=self.judge_provider_id,
                source_provider_id=source_provider_id,
                contributing_provider_ids=proposal_provider_ids,
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
                    "result": action or "UNAVAILABLE",
                    "task_id": task_id,
                    "judge_verdict": dict(verdict) if isinstance(verdict, Mapping) else {},
                    "council": dict(council),
                }
                try:
                    append_evidence(event)
                except Exception as exc:
                    raise EvidenceWriteError("escrow evidence append failed") from exc
                execution.update({"status":"ESCROW_PENDING_REVIEW","action":action,
                                  "council":dict(council),"judge_verdict":verdict})
                raise EscrowPending(f"{action or council_action or 'INVALID'} requires review")
            output = judged.get("final_output")
            if not isinstance(output, str) or not output.strip() or output != council_candidate:
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
                "source_provider_id": source_provider_id,
            })
            return {
                "status": "PASS",
                "output": output,
                "output_hash": output_hash,
                "judge_verdict": dict(verdict),
                "source_provider_id": source_provider_id,
            }

        try:
            receipt = run_dual_gated(
                proof=authorization_proof,
                verification_key=verification_key,
                task_id=task_id,
                owner_id=owner_id,
                required_scope=required_scope,
                route_and_judge=route_and_judge,
                evidence_sink=append_evidence,
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
            "evidence_receipt": {
                "event_type": receipt.evidence_receipt.event_type,
                "task_id": receipt.evidence_receipt.task_id,
                "event_id": receipt.evidence_receipt.event_id,
                "event_hash": receipt.evidence_receipt.event_hash,
                "signature": receipt.evidence_receipt.signature,
                "sequence": receipt.evidence_receipt.sequence,
            },
        }
