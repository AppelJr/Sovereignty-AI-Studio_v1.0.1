# Sovereignty AI Studio — Resilience Contract

## Ownership and routing

Sovereignty AI Studio remains the control surface and coordination hub. Genesis creates and validates task envelopes; GateOne and Sovereignty AI Gate decide authorization; GitSovereign is the certificate/admission boundary; DevAssist420 routes work; SCAR records evidence. A router, council, voice input, or provider response never grants authority.

## Recovery behavior

1. Monitor each component independently: dashboard, Python bridge, Node bridge, DevAssist router, GateOne, Sovereignty AI Gate, GitSovereign admission/certificate service, risk engine, SCAR, model adapters, and optional voice/device modules.
2. On failure, mark the component degraded/offline, stop sending new requests to it, retain evidence, and alert the owner.
3. A backup may be attempted only if it independently passes health checks, current policy, identity/certificate verification, revocation/freshness checks, and scope/capability authorization.
4. Preserve the original request authorization and request ID; do not broaden scope or load memory implicitly during failover.
5. Require SCAR to confirm persistence before invoking a candidate. Record the attempt and outcome. If SCAR persistence fails, halt execution.
6. If no candidate passes, return a controlled unavailable/denied result. Never bypass GateOne or GitSovereign to maintain uptime.
7. A repaired component stays quarantined until health, integrity, policy, and integration checks pass again. Owner retains final production promotion.

## Merkle / SCAR integrity

`backend/sovereign_resilience.py` provides domain-separated SHA3-512 Merkle leaves/nodes, inclusion proofs, strict SCAR JSONL parsing, and an explicit dual-hash mode that fails if BLAKE3 is unavailable. Merkle roots are not signatures. ML-DSA signing requires an injected real signer and public key; no placeholder attestation is accepted.

The helper expects each SCAR JSONL record to contain a non-empty `hash` field. It does not silently skip malformed records. Confirm compatibility with the canonical SCAR writer before production use.

## Production gates

- [ ] All target components have concrete local health/admission adapters.
- [ ] SCAR append receipt is cryptographically verified and durable before side effects.
- [ ] Merkle proof tests pass against the canonical SCAR hash format.
- [ ] GateOne and GitSovereign signatures, key provenance, freshness, and revocation are verified by production implementations.
- [ ] iPhone dashboard → bridge → authorized model → response round trip passes over the configured secure transport.
- [ ] Failure injection demonstrates quarantine, alerting, backup admission, recovery, and readmission.
- [ ] Owner reviews the evidence and explicitly promotes production.

A passing unit test for a helper is not evidence that the full system is live or certified.
