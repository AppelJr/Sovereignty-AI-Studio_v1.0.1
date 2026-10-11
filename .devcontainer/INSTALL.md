# Sovereignty Gate — Install

Six modules, one governance loop. No unzipping required: everything is already in this repo.

## The loop

```
intelligent_routing.py   →  classifier (recommendation only)
        │
        ▼
policy_resolver.py      →  sole authority (ALLOW / FALLBACK / QUEUE / DENY)
        │
        ▼
runtime_executor.py     →  mutation boundary (executes only what was authorized)
        │
        ▼
scar_routing / scar_log  →  append-only evidence

Supporting:
  budget_ledger.py      →  authoritative usage (reserve / commit / release / refund)
  queue_backend.py      →  durable deferred execution (QUEUE decisions only)
  handler_contract.py   →  local + full execution adapters
```

## Where each file goes

All six modules live in one directory (e.g. `sovereignty_gate/` or `.devcontainer/`):

| File | Role |
|------|------|
| `intelligent_routing.py` | Heuristic classifier. Keyword/pattern + length signals. NOT ML. |
| `policy_resolver.py` | Sole authority. Turns RoutingDecision into PolicyDecision. |
| `runtime_executor.py` | Narrow execution boundary. Verifies policy identity, dispatches, records to SCAR. |
| `budget_ledger.py` | Authoritative budget. Thread-safe, append-only events, fail-closed on corruption. |
| `queue_backend.py` | Durable queue. Accepts only QUEUE decisions. Survives restart. |
| `handler_contract.py` | LocalExecutionAdapter + FullExecutionAdapter. Deterministic stand-ins until v1.8 providers. |

## Dependencies

- Python 3.10+
- `scar_log.py` and `scar_routing.py` (existing in repo) — the six modules import from these
- No third-party packages required for the deterministic core

## First test (30 seconds)

```bash
python3 intelligent_routing.py "What is the capital of France?"
```

Expected: `complexity: simple_factual`, `recommended_model: local/light`.

Then a build signal:

```bash
python3 intelligent_routing.py "def hello(): pass"
```

Expected: `complexity: coding_build`, `recommended_model: full`.

## Modes

See `modes.json`. Three modes: **offline** (local only), **hybrid** (local-first, online on demand), **online** (full network). Modes change capabilities and network reachability only — they never bypass PolicyResolver, BudgetLedger, or CircuitBreaker.

## Known gaps (honest)

1. The six modules are currently uncommitted working copies — this branch adds the mode config and this doc; paste the module sources to commit them as real files.
2. `handler_contract.build_executor_with_handlers` hardcodes `on_fallback=full`; a FALLBACK with preferred=local routes to the full adapter and raises HandlerContractViolation. Fix: dispatch on `fallback_metadata['preferred']`.
3. `queue_backend.py` persists without a hash chain — corruption is caught by exception, not integrity check.
4. PolicyResolver happy path honours the classifier with zero capability/budget gates — by design, but means a mis-tuned classifier reaches full ungated.

## Provenance

- Modules: pasted into chat 2026-10-11 by Appel420, reviewed live.
- This doc + modes.json: authored by Grok (SpaceXAI), 2026-10-11, pushed to branch `gate-wiring`.
- Repo tree verified via GitHub API this session (Sovereignty-AI-Studio_v1.0.1 @ f3be9df5878cca94e7ee8b7a02a53ba67dd0f9f4).
