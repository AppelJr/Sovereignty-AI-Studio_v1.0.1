# Eighteen-repository Chain of Command integration map

This is a role-aware integration contract. The Studio is the canonical orchestration
implementation. Consumer repositories must not receive a second copy of authority,
router, Heavy Judge, or SCAR ledger logic.

| Repository | Integration role | Contract boundary |
|---|---|---|
| Sovereignty-AI-Gate | Root authority | Issues/verifies owner, device, task, scope and policy proofs. |
| keycloak | Identity upstream | Identity federation only; never treated as Sovereignty authorization by itself. |
| grok-build | Human acceptance policy | Implements the eight-state proposal/approval gate and binds its approval to Gate proof. |
| Genesis | Smart routing | Emits a RouteDecision; cannot authorize or release output. |
| Sovereignty-Risk-Engine-Runtime-Assurance | Risk and policy evaluation | Supplies risk evidence and policy decisions to the Judge; does not bypass Gate. |
| Sovereignty-AI-Studio_v1.0.1 | Canonical orchestration | Hosts Heavy Judge, dual-gate path, Council, OUTENV and adapters. |
| Grok-4.7-ChatGPT-6.1-Claude-5.5-Skeleton | Runtime host | Calls Studio contracts through explicit adapters; no duplicate authority. |
| mldsa-native | Cryptographic provider | Supplies ML-DSA implementation; signing is injected and verified, never simulated. |
| FamilyGuard | Device/family consumer | Uses Gate proof and release receipt; local safety policy remains scoped. |
| Sovereignty-AI-Gate_Q-Resist | Integrity consumer | Integrity alerts can request YANK/escrow; HTML prototype is not enforcement. |
| Sovereign-piper1-gpl-Voice | Voice output | Receives only released OUTENV; voice is not identity or authorization. |
| NeuralScene-iOS | iOS/render consumer | Displays verified output and provenance metadata; does not grant authority. |
| every-cloud-for-everyone | Privacy enforcement | Enforces destination/data policy before any external transport. |
| ISO-UNC-AI | Compliance validation | Validates control/evidence mappings; no runtime authorization. |
| ciso-assistant-community | GRC evidence consumer | Receives sanitized, attributable audit evidence only. |
| marketplace-fedramp-gov-data | Compliance data | Provides control catalog references; never treated as policy authority. |
| Sovereignty_airplane-mode | Offline-mode enforcement | Enforces network mode; offline must never silently fall back to cloud. |
| Sovereignty-QuantumEEGNet | Research consumer | Receives approved research tasks/results; no medical advice or authority override. |

## Required event contract

Consumers exchange only versioned envelopes and evidence references:
`request_id`, `task_id`, `owner_id`, `device_id`, `scope`, `policy_hash`,
`route_id`, `judge_verdict_id`, `output_hash`, `signature_ref`,
`scar_event_id`, `repmhl_record_id`, and `status`.

## Status semantics

- `WIRED`: executable adapter is connected and integration tests pass.
- `DECLARED`: repository role and contract are registered; no runtime connection claimed.
- `BLOCKED`: dependency or permission prevents integration.
- `NOT_RUN`: integration tests have not been executed.

Do not report a repository as WIRED based on a manifest, README, import, or file copy.
