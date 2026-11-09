# Heavy Judge integration status

## Current implementation on this branch

- \`sovereign_core/heavy_judge.py\` is the deterministic behavioral gate. It applies conservative configured signal thresholds and returns PASS / REWRITE / YANK. It is not a calibrated ML risk model and does not establish authorization.
- \`sovereign_core/judge_composition.py\` composes the advisory model review with the deterministic behavioral gate. The most restrictive action wins; COUNCIL is a hold state. The model layer cannot authorize release or downgrade a behavioral denial.
- \`sovereign_core/smart_provider_router.py\` now requires an injected \`ComposedHeavyJudge\`. The previous optional/legacy judge construction path is rejected. The router verifies that all three Council lanes are present, requires the aggregate action, and withholds every non-PASS result.
- \`backend/coordination/dual_gate_path.py\` remains the two-boundary wrapper: Gate proof verification before routing, followed by output digest verification and mandatory release evidence before output is returned.
- \`tests/test_smart_provider_router_composed.py\` covers composed PASS, model escalation, behavioral YANK, invalid Gate proof, missing Council lanes, legacy judge rejection, and release-evidence failure.

## Explicit boundaries and unresolved dependencies

1. **Model backend:** the composed judge requires an owner-startup-injected backend implementing \`evaluate(candidate, context)\`. \`HEAVYJUDGE_MODEL\` must be configured. This patch does not create provider credentials, select a production model, or perform a model request.
2. **Behavioral evaluator:** the deterministic signal evaluator is a conservative guardrail, not calibrated risk scoring. It must not be represented as a trained or production-validated risk model.
3. **Evidence persistence:** the router accepts an evidence sink and fails closed when required appends fail. The durability, signature provenance, retention, and tamper resistance of the injected sink must be verified against the canonical SCAR/REPMHL implementation separately. Backend access telemetry is required on successful reviews; failed backend calls are recorded with UNKNOWN access state rather than invented booleans.
4. **Authorization:** Gate proof verification remains separate from Heavy Judge. A judge PASS is never an authorization grant.
5. **Asynchronous provider path:** Gate proof verification occurs before provider requests. Provider proposals must pass through the injected Council adapter; the adapter must return all three attributable lane proposals (Grok, GPT/Codex, Claude), lane votes, a consolidated candidate, and source attribution. The composed Judge reviews that Council candidate. The router requires an explicitly configured Judge provider identity that is distinct from every contributing provider identity. Missing or malformed Council data, Judge identity overlap, non-PASS verdicts, and Judge unavailability withhold output. Health checks remain configuration-only and do not probe provider APIs.
6. **Exact verdict binding:** governed Judge verdicts bind task ID, Gate policy hash, candidate SHA3-512 digest, Judge identity, Judge provider identity, source identity, and contributing provider identities. Gate 2 re-verifies the original Gate proof (owner, task, scope, policy, decision, and expiry), then checks those verdict fields against the exact output before release. A changed candidate or expired proof cannot reuse a previous PASS.
7. **Evidence acknowledgment:** Gate 2 requires the evidence sink to return a structured `EvidenceAppendReceipt` bound to the release event type and task ID, with a non-empty event ID, SHA-256 event hash, signature text, and sequence. `SCARLedgerSink` builds this acknowledgment from the appended SCAR event. A successful callback returning no receipt is insufficient.
8. **Durability boundary:** the existing `SCARLedger` remains process-memory-only. The append receipt confirms that the configured sink appended and returned a signed SCAR event; it does not establish persistence across process restarts or independently verify the root-of-trust signature. Hash-chain verification is not a substitute for signature verification or durable anchoring.
9. **Retry / escrow:** non-PASS output is withheld. Judge backend or evaluator unavailability is represented as `UNAVAILABLE` and held; there is no silent substitution. A revised candidate must pass through Council and receive a new Judge verdict. Owner-mediated bounded rewrite/retry remains a separate, unimplemented controller.

## Validation state

- Branch and source edits: committed on the dedicated agent branch.
- Automated tests: NOT RUN in this environment.
- Application startup: NOT RUN.
- Provider/model requests: NOT RUN.
- Durable SCAR/REPMHL integration: NOT VERIFIED.
- Merge, deployment, and production authorization: NOT PERFORMED.

Do not promote this branch until the focused tests, broader regression suite, evidence-store integration tests, and owner review pass.


## Async router dual-gate patch (PR #207)

- Branch: `agent/async-router-dual-gate-20261108`; target: protected `Collaboration`.
- Gate proof validation occurs before provider calls and binds owner, task, required scope, decision, and expiry.
- The composed judge must return exact-candidate PASS; Gate 2 verifies SHA3-512 and appends release evidence before the response is returned.
- Provider fallback is limited to HTTP transport failures and retryable 429/5xx responses. Non-retryable provider failures, malformed results, judge failures, missing telemetry, and evidence failures stop.
- Regression evidence on the PR merge candidate: focused Python suite **39 passed**; offline dispatcher suite **5 passed**; Node integration checks **5 passed**; Pylint, sovereign-guard, Quart App CI, CI, OAuth generator, static security, local unit CI, and Docker contract/build checks reported success. Dependency requirements validation was still running at the time of this note.
- Device/iPhone runtime and production provider requests remain NOT RUN. The patch is not merged or promoted.
