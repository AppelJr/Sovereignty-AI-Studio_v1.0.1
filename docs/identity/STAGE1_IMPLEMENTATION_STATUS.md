# Sovereignty Identity Core — Stage 1 implementation record

Status: IMPLEMENTATION IN PROGRESS
Architecture baseline: ACCEPTED
Production: BLOCKED
Execution evidence: NOT RUN IN this environment

## Scope delivered on this branch

- Added a separate backend/identity/sovereign_identity_core.js module.
- Preserved the existing identity_adapter.js compatibility boundary.
- Defined OWNER, HUMAN, DEVICE, SERVICE, and FEDERATION_PARTNER principal classes.
- Enforced one canonical OWNER principal at startup; root bootstrap requires a separately injected owner-proof verifier and a SCAR-backed state commit.
- Added Gate.One-gated principal registration, activation, suspension, and revocation.
- Added device-key challenge, signature verification, explicit owner approval, and revocation.
- Added trust-anchor records for SAML2 signing, OIDC JWKS, and SCIM2 provisioning purposes, including predecessor-bound rotation.
- Added Gate.One-gated federation alias registration, bound to an active federation-partner principal and a valid trust anchor.
- Federation resolution requires an injected protocol assertion verifier, a registered active trust anchor, and an explicit alias; it ignores owner/admin/root/group claims and returns authorization NOT_EVALUATED.
- Added a Stage 1 test file and wired it into npm test.

## Explicit boundaries

- No SAML, OIDC, OAuth, or SCIM protocol server/client implementation.
- No token parsing or cryptographic verification of external assertions in this module. Protocol adapters must validate those assertions before calling the resolver.
- OAuth access tokens are not accepted as identity proof.
- No production key ceremony, hardware attestation verification, or production persistence adapter.
- Gate.One remains an injected independent authorization dependency.
- storage.commit(snapshot, scarEvent) MUST atomically persist state and evidence. The in-memory test adapter is not production-safe.
- HARDWARE_ASSERTED_UNVERIFIED is a label only, not verified hardware attestation.

## Known remaining work

- Run the new Node test suite and the existing repository test suite in CI.
- Complete and map all fifteen design-plan negative cases (ID-001 through ID-015) to executable tests.
- Add persistence adapter with transaction semantics, integrity verification, crash recovery, and SCAR signature/checkpoint support.
- Add scheduled cleanup for expired pending enrollment challenges and complete expiry/replay evidence coverage.
- Add trust-anchor revocation/rotation verification and recovery tests; principal and device revocation transitions are implemented.
- Implement protocol-specific assertion validators that cryptographically bind signatures/JWKS/certificates to the registered trust-anchor fingerprint; the current core only consumes an injected validator result.
- Closed the existing Authority Gate participant permission-omission path: participant actions now require an exact action-matching capability; missing, mismatched, and wildcard-only permissions deny. Regression tests are included.
- Add schema validation and independent security review.

## Verification

- Source review: performed against Collaboration branch files.
- New test execution: prior commit passed Node.js CI; latest bootstrap, validator, and lifecycle changes are awaiting a fresh CI run.
- Existing test suite: NOT RUN.
- CI: prior commit passed core Node.js and security checks; latest changes are awaiting a fresh CI run.
- Production deployment: BLOCKED.

Do not represent this branch as production-ready or as having passed the fifteen-case acceptance gate.
