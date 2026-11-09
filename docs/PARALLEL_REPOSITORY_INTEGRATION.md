# Twelve-Repository Parallel Integration

## Status

This is an integration plan and offline checkout-preflight implementation, not a claim that all twelve repositories are already executing together.

- Contract: `SOVEREIGNTY_PARALLEL_REPOSITORY_RUNTIME/1.0`
- Registry: `integration/parallel-repository-registry.json`
- Workspace manifest: `integration/local-repositories.json`
- Planner/preflight: `scripts/parallel_repository_runtime.py`
- Tests: `tests/test_parallel_repository_runtime.py`
- Default mode: LOCAL
- Network access: none during preflight
- Repository execution: disabled until a reviewed adapter contract exists

## Repository roles

| Repository | Role | Integration state |
|---|---|---|
| Sovereignty-AI-Studio_v1.0.1 | Integration host | Host |
| Genesis | Task origin and routing | Adapter unbound |
| gateone | Admission gateway | Adapter unbound |
| Sovereignty-AI-Gate | Identity, authorization, SCAR | Adapter unbound |
| Sovereignty-Risk-Engine-Runtime-Assurance | Risk and runtime assurance | Adapter unbound |
| Grok-4.7-ChatGPT-6.1-Claude-5.5-Skeleton | Model router/runtime host | Adapter unbound |
| ISO-UNC-AI | Independent validation | Adapter unbound |
| mldsa-native | ML-DSA native primitive | Native adapter unbound |
| Git-Sovereign | Governed Git adapter | Adapter unbound |
| every-cloud-for-everyone | Client-side encryption | Swift adapter unbound |
| NeuralScene-iOS | Verified iOS display | iOS adapter unbound |
| Sovereignty-AI-Gate_DevAssist420 | Device assistant client | Client adapter unbound |

The registry deliberately distinguishes an integration role from an executable adapter. A repository checkout or README does not establish a callable runtime API.

## Parallel execution contract

The dependency planner builds a directed acyclic graph (DAG). Repositories in the same dependency layer are eligible for concurrent work only after their dependencies are satisfied and the owner-authorized policy gate admits the task.

```text
Owner / canonical state
        |
        v
Genesis task envelope
        |
        v
GateOne admission
        |
        v
Sovereignty-AI-Gate authorization
        |
        v
Risk / runtime assurance
        |
        +-------------------------------+
        |               |               |
        v               v               v
   Model router    ISO-UNC-AI      Git-Sovereign
        |               |               |
        +---------------+---------------+
                        |
                        v
             Independent validation
                        |
                        v
                 Human decision
                        |
                        v
                 SCAR evidence
```

Crypto, iOS, and cloud-encryption components have distinct build and runtime constraints. They are not launched as generic server processes.

## Security invariants

1. Routing is not authorization.
2. A digest is not an approval or signature.
3. Council/risk results are evidence, not authority grants.
4. A client cannot grant its own capabilities.
5. No provider or cloud network call occurs in LOCAL mode.
6. Git push, merge, deletion, deployment, and protected-branch mutation require separate explicit capabilities and approval.
7. Missing, mismatched, or unbound adapters fail closed.
8. No repository code is executed by discovery or preflight.
9. SCAR records should bind the task, actor, policy decision, participating repository commit identities, result, and evidence digests.
10. A repository's default branch is not modified by this integration branch.

## Run offline preflight

From the Studio repository:

```bash
python3 scripts/parallel_repository_runtime.py
python3 scripts/parallel_repository_runtime.py --json
python3 -m unittest tests.test_parallel_repository_runtime -v
```

Set `SOVEREIGNTY_WORKSPACE` to the directory containing sibling checkouts. The Studio checkout is resolved from `SOVEREIGNTY_STUDIO_ROOT`, or defaults to the current Studio repository root.

The preflight checks local Git checkout identity and prints dependency layers. It does not clone, fetch, install packages, start services, invoke providers, or mutate any sibling repository.

## Acceptance gates

- [ ] All twelve local checkouts are present and origin-verified.
- [ ] Genesis TaskEnvelope and RouteDecision adapter has contract tests.
- [ ] GateOne admission API and Sovereignty-AI-Gate authorization API are independently verified.
- [ ] Risk engine adapter passes its repository-native tests.
- [ ] Model router supports bounded parallel fan-out, cancellation, deadlines, and provenance.
- [ ] ISO-UNC-AI consumes immutable evidence references and emits validation results.
- [ ] ML-DSA native build/link adapter passes upstream and integration vectors.
- [ ] Git-Sovereign enforces read-only defaults and separately gated mutations.
- [ ] Swift cloud-encryption library has a reviewed adapter; no cloud egress in LOCAL.
- [ ] NeuralScene builds and passes device-side validation on macOS/Xcode.
- [ ] DevAssist420 client cannot bypass Gate authorization.
- [ ] Cross-repository failure injection, timeout, cancellation, duplicate request, and SCAR verification tests pass.
- [ ] Owner reviews evidence and explicitly accepts promotion.

Until these gates pass, runtime status remains `BLOCKED` rather than `READY`.
