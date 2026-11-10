# Sovereignty Identity Core — Stage 1 implementation record

Status: IMPLEMENTATION IN PROGRESS
Architecture baseline: ACCEPTED
Production: BLOCKED
Execution evidence: NOT RUN IN this environment

## Scope delivered on this branch

- Added a separate backend/identity/sovereign_identity_core.js module.
- Preserved the existing identity_adapter.js compatibility boundary.
- Defined OWNER, HUMAN, DEVICE, SERVICE, and FEDERATION_PARTNER principal classes.
- Enforced one canonical OWNER principal at startup.
- Added Gate.One-gated principal registration and activation.
- Added device-key challenge, signature verification, explicit owner approval, and revocation.
- Added trust-anchor records for SAML2 signing, OIDC JWKS, and SCIM2 provisioning purposes.
- Added Gate.One-gated federation alias registration, bound to an active federation-partner principal and a valid trust anchor.
- Federation resolution ignores owner/admin/root/group claims and returns authorization NOT_EVALUATED.
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
- Add bounded pending-enrollment limits, cleanup/expiry, and explicit challenge replay evidence.
- Add principal suspension/revocation lifecycle and trust-anchor revocation/rotation state transitions.
- Bind protocol assertion validation to the registered trust-anchor fingerprint; current resolver assumes validated protocol metadata.
- Review the existing Authority Gate permission-omission defect separately; this branch does not silently rewrite the legacy adapter/gate.
- Add schema validation and independent security review.

## Verification

- Source review: performed against Collaboration branch files.
- New test execution: NOT RUN.
- Existing test suite: NOT RUN.
- CI: NOT RUN.
- Production deployment: BLOCKED.

Do not represent this branch as production-ready or as having passed the fifteen-case acceptance gate.
