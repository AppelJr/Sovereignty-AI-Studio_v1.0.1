# Heavy Judge integration status

## Integrated in this branch

- `sovereign_core/heavy_judge.py` is the deterministic threshold gate. It validates context and score inputs, distinguishes PASS / REWRITE / YANK, and never releases an unvalidated rewrite.
- Rewrite output is treated as untrusted. It is accepted only when a separate `rewrite_risk_evaluator` is injected and returns a score below the configured rewrite threshold. Otherwise the safe replacement is returned.
- Input and final-output SHA3-512 digests are included in the verdict. An optional HMAC-SHA3-512 correlation value is added only when a key is explicitly supplied. HMAC is not described as a public-key signature.
- The audit interface is `repmhl.log(dict)`. Missing or failing audit sinks fail closed by default.
- `sovereign_core/smart_provider_router.py` requires an injected risk evaluator and applies HeavyJudge regardless of the legacy `use_judge=False` argument.
- The active async provider path in `backend/app/services/ai_router.py` now invokes HeavyJudge after a provider returns a candidate. Provider fallback occurs only for provider-call failures; judge or audit failures propagate and do not cause another provider request.
- `docs/architecture/DEVASSIST420_HEAVY_JUDGE_FLOW.mmd` records the target end-to-end control flow and preserves Gate.One as the independent authorization boundary.

## Deliberately not fabricated / still blocked

1. **Risk evaluation:** no calibrated, production risk evaluator was found in the repository. The router therefore requires injection and fails closed if absent. No synthetic scores or keyword-only confidence claims are introduced.
2. **Persistent REPMHL adapter:** the discovered `.devcontainer/repmhl(1).py` exposes `hydrate/recall/forget/list_keys`, not `log(dict)`. A compatible persistent audit adapter must be wired to the canonical SCAR/REPMHL stores before the live singleton can serve requests. The live singleton is intentionally unconfigured and blocks output.
3. **Model Council:** the repository's `backend/coordination/CouncilResult` concerns agent branch/scope coordination; it is not a provider-response consensus engine. The legacy longest-output council is not reused. A provider council requires a separately defined evaluator and structured vote contract.
4. **Retry / Escrow:** the diagram describes the target retry-budget and second-review flow. This branch does not yet implement the full bounded retry controller or owner escrow workflow.
5. **Provider health:** the existing async `AIRouter` has sequential provider fallback. Its current provider `health_check` methods only verify key configuration; they are not live readiness probes. This branch does not claim health-based failover.
6. **Authorization:** Gate.One remains independent. A Heavy Judge PASS is a content-quality decision, not an authorization grant.

## Validation state

- Focused tests were added for threshold actions, rewrite validation, invalid scores, mandatory judging, and audit failure.
- Tests and application startup have **not been executed** in this environment.
- No external provider request, production database migration, merge, or deployment was performed.
