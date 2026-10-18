# GATEONE PQC Authenticator — Deployment Guide

**File:** `keycloak/gateone-pqc-authenticator.js`  
**Version:** v1.0  
**Owner:** AppelJr  
**Provenance:** Grok (xAI) drafted; AppelJr owns and deploys.  
**Timestamp:** 2026-10-08T20:30:00Z

## What it does

Keycloak Script Authenticator that POSTs a client-supplied `attestation_token`
(JSON: payload, signature, public_key, optional tpm_quote) to the GATEONE
FastAPI verifier (`gateone_pqc_verifier.py`) for ML-DSA-87 signature + TPM 2.0
quote verification. On `valid=true`, authentication succeeds and optional user
attributes (`pqc_node_id`, `pqc_algorithm`) are set.

## Security (v1.0)

- **mTLS:** client certificate (PKCS12) presented to the verifier; CA cert
  pinned via TrustManager. Configure `GATEONE_CLIENT_CERT_PATH`,
  `GATEONE_CLIENT_CERT_PASSWORD`, `GATEONE_CA_CERT_PATH`.
- **Bearer auth:** `Authorization: Bearer <GATEONE_VERIFIER_TOKEN>` header on
  every request. The FastAPI verifier now enforces this token.
- **Timeouts:** 5s connect, 10s read.
- **Fail-closed:** any non-200, parse error, or exception calls `context.failure()`.
- **Rate limiting:** 30 requests/minute per IP on the verifier.
- **Audit logging:** every verification attempt logged to SCAR log.
- **CORS:** locked to Keycloak origin only.

## What is still NOT done

- Session store is in-memory (lost on restart) — no persistent revocation.
  Fix: configure PostgreSQL in keycloak.conf (db=postgres) — already
  templated in the production config.
- TLS certificates for Keycloak and the verifier must be generated with
  the CA tooling in `ca/` and deployed to the hosts.
- DNS for gateone.sovereignty.local must point at the Keycloak host.

## Honest status

This is a **production integration** with the security gaps closed:
bearer auth enforced, rate limiting, audit logging, mTLS, real hostname.
Remaining work is deployment plumbing (certs, DNS, Postgres), not code.

## Deploy steps

1. Enable Keycloak Script Authenticator feature flag.
2. Place `gateone-pqc-authenticator.js` in `providers/`.
3. Generate client cert + CA per `ca/ca.cnf` / `ca/Makefile` (private key stays local,
   never committed — see `.gitignore`).
4. Set environment variables or edit keycloak.conf SPI properties before deploy.
5. Run the GATEONE verifier: `python gateone_pqc_verifier.py` (binds 0.0.0.0:8444).
6. Point DNS for gateone.sovereignty.local at the Keycloak host.
7. Test with a valid attestation token; confirm `context.success()`.
