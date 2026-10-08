# GATEONE PQC Authenticator — Deployment Guide

**File:** `keycloak/gateone-pqc-authenticator.js`  
**Version:** v0.2  
**Owner:** AppelJr  
**Provenance:** Grok (xAI) drafted; AppelJr owns and deploys.

## What it does

Keycloak Script Authenticator that POSTs a client-supplied `attestation_token`
(JSON: payload, signature, public_key, optional tpm_quote) to the GATEONE
FastAPI verifier (`gateone_pqc_verifier.py`) for ML-DSA-87 signature + TPM 2.0
quote verification. On `valid=true`, authentication succeeds and optional user
attributes (`pqc_node_id`, `pqc_algorithm`) are set.

## Security hardening (v0.2)

- **mTLS:** client certificate (PKCS12) presented to the verifier; CA cert
  pinned via TrustManager. Configure `GATEONE_CLIENT_CERT_PATH`,
  `GATEONE_CLIENT_CERT_PASSWORD`, `GATEONE_CA_CERT_PATH`.
- **Bearer auth:** `Authorization: Bearer <GATEONE_VERIFIER_TOKEN>` header on
  every request. Configure `GATEONE_VERIFIER_TOKEN`.
- **Timeouts:** 5s connect, 10s read.
- **Fail-closed:** any non-200, parse error, or exception calls `context.failure()`.

## What is still NOT done

- Verifier endpoint (`/verify-attestation`) still needs its own auth layer
  (the authenticator now sends a bearer token, but the FastAPI service must
  enforce it).
- `keycloak.conf` hostname is still the stock template (commented out).
- Session store is in-memory (lost on restart) — no persistent revocation.
- No rate limiting on the authenticator itself.
- No audit logging of auth attempts.

## Honest status

This is a **lab/dev integration**. It is not production-ready for enterprise
deployment. The pieces (ML-DSA-87 verifier, TPM quote checking, mTLS wiring,
bearer auth) are real and tested in isolation. The deployment is not.

## Deploy steps (lab only)

1. Enable Keycloak Script Authenticator feature flag.
2. Place `gateone-pqc-authenticator.js` in `providers/`.
3. Generate client cert + CA per `ca.cnf` / `Makefile` (private key stays local,
   never committed — see `.gitignore`).
4. Set environment variables or edit the script before deploy.
5. Run the GATEONE verifier on a host reachable from Keycloak.
6. Test with a valid attestation token; confirm `context.success()`.
