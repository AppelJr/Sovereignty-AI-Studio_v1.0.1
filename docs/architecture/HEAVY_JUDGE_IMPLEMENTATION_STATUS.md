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
5. **Other provider path:** \`backend/app/services/ai_router.py\` is a separate asynchronous provider path and is not changed by this router-seam patch. It must not be claimed to inherit this dual-gate path.
6. **Retry / escrow:** non-PASS output is withheld and an escrow event is appended. This patch does not implement owner-mediated second review or a bounded rewrite/retry controller.

## Validation state

- Branch and source edits: committed on the dedicated agent branch.
- Automated tests: NOT RUN in this environment.
- Application startup: NOT RUN.
- Provider/model requests: NOT RUN.
- Durable SCAR/REPMHL integration: NOT VERIFIED.
- Merge, deployment, and production authorization: NOT PERFORMED.

Do not promote this branch until the focused tests, broader regression suite, evidence-store integration tests, and owner review pass.
