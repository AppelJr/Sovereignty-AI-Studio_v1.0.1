"""Governed Chain of Command pipeline.

Provider adapters are injected; this module never fabricates model responses,
authorization, signatures, or audit success. Routing is advisory. Only a verified
Gate proof authorizes the request. A missing lane, judge, signer, or evidence
sink cannot be silently treated as PASS.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any, Callable, Mapping, Sequence


LANES = ("grok", "gpt_codex", "claude")
ACTIONS = frozenset({"PASS", "REWRITE", "YANK"})
EvidenceSink = Callable[[dict[str, Any]], Any]
OwnerAuthorizer = Callable[["ChainRequest"], Mapping[str, Any]]
AuthorizationVerifier = Callable[[str, "ChainRequest"], Mapping[str, Any]]
ReleaseVerifier = Callable[[Mapping[str, Any], "ChainRequest", str, str], Any]
RouteSelector = Callable[["ChainRequest"], Mapping[str, Any]]
LaneAdapter = Callable[[dict[str, Any]], Mapping[str, Any]]
RewriteHandler = Callable[[dict[str, Any]], str]
Signer = Callable[[bytes], str]


class ChainOfCommandError(RuntimeError):
    """Base exception for a rejected or incomplete chain."""


class AuthorizationRequired(ChainOfCommandError):
    """Raised when the Gate proof is absent or does not authorize the request."""


class EvidenceWriteError(ChainOfCommandError):
    """Raised when the mandatory audit sink cannot persist an event."""


@dataclass(frozen=True, slots=True)
class ChainRequest:
    request_id: str
    owner_id: str
    prompt: str
    context: str = "general"

    def __post_init__(self) -> None:
        if not self.request_id.strip() or not self.owner_id.strip():
            raise ValueError("request_id and owner_id are required")
        if not self.prompt.strip():
            raise ValueError("prompt is required")


@dataclass(frozen=True, slots=True)
class ChainResult:
    request_id: str
    status: str
    action: str
    output: str | None
    output_hash: str | None
    signature: str | None
    attempts: int
    council: Mapping[str, Any]
    judge_verdict: Mapping[str, Any]
    escrow_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ChainOfCommand:
    """Execute Router -> three lanes -> Council -> Heavy Judge -> OUTENV.

    Required integrations are dependency-injected. No provider network calls,
    credentials, or owner authority are implemented here.
    """

    def __init__(
        self,
        *,
        owner_authorizer: OwnerAuthorizer,
        authorization_verifier: AuthorizationVerifier,
        release_verifier: ReleaseVerifier,
        route_selector: RouteSelector,
        lane_adapters: Mapping[str, LaneAdapter],
        judge: Any,
        evidence_sink: EvidenceSink,
        rewrite_handler: RewriteHandler | None = None,
        signer: Signer | None = None,
        max_rewrites: int = 2,
    ) -> None:
        missing = [lane for lane in LANES if not callable(lane_adapters.get(lane))]
        if missing:
            raise ValueError(f"all provider lanes are required; missing: {', '.join(missing)}")
        if not callable(owner_authorizer) or not callable(authorization_verifier) or not callable(release_verifier) or not callable(route_selector):
            raise TypeError("owner_authorizer, authorization_verifier, release_verifier and route_selector must be callable")
        if not callable(evidence_sink):
            raise TypeError("evidence_sink is mandatory")
        if not callable(getattr(judge, "review", None)):
            raise TypeError("judge.review must be callable")
        if max_rewrites < 0 or max_rewrites > 3:
            raise ValueError("max_rewrites must be between 0 and 3")
        self._authorize = owner_authorizer
        self._verify_proof = authorization_verifier
        self._verify_release = release_verifier
        self._route = route_selector
        self._lanes = dict(lane_adapters)
        self._judge = judge
        self._evidence = evidence_sink
        self._rewrite = rewrite_handler
        self._signer = signer
        self._max_rewrites = max_rewrites

    def run(self, request: ChainRequest) -> ChainResult:
        authorization = self._authorize(request)
        if not isinstance(authorization, Mapping):
            raise AuthorizationRequired("Gate authorization response is invalid")
        decision = str(authorization.get("decision", "")).upper()
        proof = authorization.get("gate_proof")
        if decision not in {"ALLOW", "OWNER_AUTHORIZED", "DELEGATED_AUTHORIZED"}:
            self._record(request, "AUTHORIZATION_DENIED", "DENY", "Gate denied request")
            raise AuthorizationRequired("Gate did not authorize this request")
        if not isinstance(proof, str) or not proof.strip():
            self._record(request, "AUTHORIZATION_DENIED", "DENY", "Gate proof missing")
            raise AuthorizationRequired("verified Gate proof is required")
        try:
            verified = self._verify_proof(proof, request)
        except Exception as exc:
            self._record(request, "AUTHORIZATION_DENIED", "DENY", "Gate proof verification failed")
            raise AuthorizationRequired("Gate proof verification failed") from exc
        if not isinstance(verified, Mapping):
            raise AuthorizationRequired("Gate proof verifier returned invalid claims")
        if str(verified.get("owner_id", "")) != request.owner_id:
            raise AuthorizationRequired("Gate proof owner mismatch")
        if str(verified.get("task_id", "")) != request.request_id:
            raise AuthorizationRequired("Gate proof task mismatch")
        if str(verified.get("decision", "")).upper() not in {"ALLOW", "APPROVED", "OWNER_AUTHORIZED", "DELEGATED_AUTHORIZED", "OWNER_OVERRIDE"}:
            raise AuthorizationRequired("Gate proof decision is not an allow")

        route = self._route(request)
        if not isinstance(route, Mapping):
            raise ChainOfCommandError("Smart Provider Router returned an invalid route")
        selected = tuple(route.get("selected_lanes", LANES))
        if set(selected) != set(LANES):
            raise ChainOfCommandError("the configured chain requires Grok, GPT/Codex, and Claude")

        previous_output: str | None = None
        last_council: Mapping[str, Any] = {}
        last_verdict: Mapping[str, Any] = {}

        for attempt in range(self._max_rewrites + 1):
            lane_results = self._collect_lanes(request, route, previous_output, attempt)
            last_council = self._council(lane_results)
            candidate = lane_results["gpt_codex"]["output"]

            judge_result = self._judge.review(
                original_output=candidate,
                context=request.context,
                force_judge=True,
            )
            if not isinstance(judge_result, Mapping):
                raise ChainOfCommandError("Heavy Judge returned an invalid result")
            verdict = judge_result.get("verdict")
            if not isinstance(verdict, Mapping):
                raise ChainOfCommandError("Heavy Judge verdict is missing")
            last_verdict = dict(verdict)
            judge_action = str(verdict.get("action", "")).upper()
            if judge_action not in ACTIONS:
                return self._escrow(
                    request, attempt + 1, last_council, last_verdict,
                    "Heavy Judge returned an unsupported action",
                )

            council_action = str(last_council["action"])
            if "YANK" in {judge_action, council_action}:
                return self._escrow(
                    request, attempt + 1, last_council, last_verdict,
                    "YANK: quarantine and second review required",
                )

            if judge_action == "PASS" and council_action == "PASS":
                return self._deliver(
                    request, candidate, attempt + 1, last_council, last_verdict, verified
                )

            if attempt >= self._max_rewrites or self._rewrite is None:
                return self._escrow(
                    request, attempt + 1, last_council, last_verdict,
                    "REWRITE could not be completed and revalidated",
                )

            revised = self._rewrite({
                "request": asdict(request),
                "route": dict(route),
                "lane_results": {key: dict(value) for key, value in lane_results.items()},
                "council": dict(last_council),
                "judge_verdict": dict(last_verdict),
                "attempt": attempt + 1,
                "previous_output": candidate,
            })
            if not isinstance(revised, str) or not revised.strip():
                return self._escrow(
                    request, attempt + 1, last_council, last_verdict,
                    "rewrite handler returned no validated candidate",
                )
            previous_output = revised

        return self._escrow(
            request, self._max_rewrites + 1, last_council, last_verdict,
            "retry limit reached",
        )

    def _collect_lanes(
        self,
        request: ChainRequest,
        route: Mapping[str, Any],
        previous_output: str | None,
        attempt: int,
    ) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        for lane in LANES:
            raw = self._lanes[lane]({
                "request": asdict(request),
                "route": dict(route),
                "previous_output": previous_output,
                "attempt": attempt,
            })
            if not isinstance(raw, Mapping):
                raise ChainOfCommandError(f"{lane} lane returned invalid data")
            output = raw.get("output")
            action = str(raw.get("recommendation", "YANK")).upper()
            confidence = raw.get("confidence", 0.0)
            if not isinstance(output, str) or not output.strip():
                raise ChainOfCommandError(f"{lane} lane returned no output")
            if action not in ACTIONS:
                raise ChainOfCommandError(f"{lane} lane returned an unsupported recommendation")
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
                raise ChainOfCommandError(f"{lane} confidence must be numeric")
            if not 0.0 <= float(confidence) <= 1.0:
                raise ChainOfCommandError(f"{lane} confidence is outside [0, 1]")
            results[lane] = {
                "output": output,
                "recommendation": action,
                "confidence": float(confidence),
                "rationale": str(raw.get("rationale", "")),
            }
        return results

    @staticmethod
    def _council(lanes: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
        recommendations = {name: str(lanes[name]["recommendation"]) for name in LANES}
        if "YANK" in recommendations.values():
            action = "YANK"
        elif any(value == "REWRITE" for value in recommendations.values()):
            action = "REWRITE"
        else:
            action = "PASS"
        return {
            "action": action,
            "votes": recommendations,
            "vote_count": len(recommendations),
            "consensus": action == "PASS" and len(set(recommendations.values())) == 1,
        }

    def _deliver(
        self,
        request: ChainRequest,
        output: str,
        attempts: int,
        council: Mapping[str, Any],
        verdict: Mapping[str, Any],
        verified_claims: Mapping[str, Any],
    ) -> ChainResult:
        digest = hashlib.sha3_512(output.encode("utf-8")).hexdigest()
        output_hash = f"sha3-512:{digest}"
        try:
            self._verify_release(verified_claims, request, output, output_hash)
        except Exception as exc:
            raise EvidenceWriteError("post-judge release gate failed; output withheld") from exc
        signature = self._signer(bytes.fromhex(digest)) if self._signer else None
        result = ChainResult(
            request_id=request.request_id,
            status="PASS",
            action="PASS",
            output=output,
            output_hash=output_hash,
            signature=signature,
            attempts=attempts,
            council=dict(council),
            judge_verdict=dict(verdict),
        )
        self._record(request, "OUTENV_RELEASED", "PASS", "Verified output released",
                     output_hash=result.output_hash, attempts=attempts)
        return result

    def _escrow(
        self,
        request: ChainRequest,
        attempts: int,
        council: Mapping[str, Any],
        verdict: Mapping[str, Any],
        reason: str,
    ) -> ChainResult:
        self._record(request, "ESCROW_PENDING_REVIEW", "YANK", reason, attempts=attempts)
        return ChainResult(
            request_id=request.request_id,
            status="ESCROW_PENDING_REVIEW",
            action="YANK",
            output=None,
            output_hash=None,
            signature=None,
            attempts=attempts,
            council=dict(council),
            judge_verdict=dict(verdict),
            escrow_reason=reason,
        )

    def _record(
        self,
        request: ChainRequest,
        event: str,
        result: str,
        why: str,
        **extra: Any,
    ) -> None:
        record = {
            "who": "ChainOfCommand",
            "what": event,
            "when": datetime.now(timezone.utc).isoformat(),
            "where": "Sovereignty-AI-Studio_v1.0.1",
            "why": why,
            "how": "SmartProviderRouter -> provider lanes -> Council -> HeavyJudge",
            "authorization": "gate-proof-verified" if event != "AUTHORIZATION_DENIED" else "denied",
            "memory_loaded": False,
            "network_accessed": False,
            "files_changed": [],
            "result": result,
            "request_id": request.request_id,
            **extra,
        }
        try:
            self._evidence(record)
        except Exception as exc:
            raise EvidenceWriteError("SCAR/REPMHL evidence write failed; chain halted") from exc
