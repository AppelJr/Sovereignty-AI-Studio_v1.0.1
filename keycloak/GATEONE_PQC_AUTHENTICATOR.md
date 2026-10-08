# GATEONE PQC Script Authenticator for Keycloak

**File:** `keycloak/gateone-pqc-authenticator.js`
**Status:** Integration stub — lab/dev only, not production-ready.

## What it does

A Keycloak **Script Authenticator** that challenges the client for an
`attestation_token` form parameter and verifies it against the GATEONE
PQC verifier (`gateone_pqc_verifier.py`, ML-DSA-87 / Dilithium + TPM 2.0).

- On `valid: true` → `context.success()`, optionally sets user attributes
  `pqc_node_id` and `pqc_algorithm`.
- On anything else → `context.failure()`.

## What it does NOT do (yet)

- No mTLS between Keycloak and the verifier.
- No authentication on the `/verify-attestation` endpoint itself.
- No retry, circuit-breaker, or structured error handling.
- No rate limiting on the authenticator.
- The verifier endpoint is bound to 127.0.0.1 by default — it is not
  reachable from a Keycloak host on another machine without reconfiguration.
- The `.devcontainer/keycloak.conf` in this repo is still the stock
  template with hostname commented out.

## Deployment steps (lab only)

1. Enable the Script Authenticator feature in Keycloak
   (Admin Console → Realm Settings → Themes/Features, or start with
   `--features=scripts`).
2. Upload `gateone-pqc-authenticator.js` as a Script Authenticator
   (Authentication → Flows → Add execution → Script).
3. Bind it into the desired flow (browser or direct grant) before
   access is granted.
4. Ensure the GATEONE verifier is running and reachable from the
   Keycloak host, and set `GATEONE_VERIFIER_URL` in the script.
5. Generate a real attestation token with a real TPM quote — the
   verifier fails closed when the TPM quote is missing or invalid.

## Related files in this repo

- `gateone_pqc_verifier.py` — FastAPI verifier (ML-DSA-87, fail-closed TPM).
- `backend/pqc/attestation_token.py` — token generator + verifier.
- `.devcontainer/keycloak.conf` — stock Keycloak config template.

## Provenance

- Pushed by Grok (xAI) via GitHub connector on behalf of AppelJr.
- Commit message: "Add GATEONE PQC Script Authenticator for Keycloak".
- Based on the authenticator script provided by AppelJr; modified with
  timeouts, UTF-8 handling, attribute setting, and an explicit
  non-production status header.
