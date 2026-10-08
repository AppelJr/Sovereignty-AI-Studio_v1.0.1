# GATEONE mTLS Setup Guide

## What this closes

The Keycloak script authenticator (`keycloak/gateone-pqc-authenticator.js`) POSTs attestation tokens to the GATEONE verifier's `/verify-attestation` endpoint. Before this setup, that connection was plaintext HTTP to an unauthenticated localhost service. This closes the **mTLS gap**: Keycloak now presents a client certificate, and the verifier only accepts connections from it.

## Files

| File | Purpose |
|------|--------|
| `ca.cnf` | OpenSSL config: P-384 root CA, server/client cert extensions, SANs |
| `Makefile` | Generates CA, service cert (90-day), and Keycloak client cert (90-day) |

## Steps

1. **Generate the CA and certs:**
   ```bash
   make all
   ```
   This creates:
   - `ca/certs/ca.crt` - root CA (10-year, P-384, SHA-384)
   - `ca/private/ca.key` - CA private key (**chmod 600, never commit**)
   - `gateone-server.crt` / `gateone-server.key` - verifier's server cert (90-day)
   - `keycloak-client.crt` / `keycloak-client.key` - Keycloak's client cert (90-day)

2. **Configure the GATEONE verifier for mTLS:**
   Edit `gateone_pqc_verifier.py` to run uvicorn with SSL:
   ```python
   uvicorn.run(app, host="127.0.0.1", port=9899,
               ssl_certfile="gateone-server.crt",
               ssl_keyfile="gateone-server.key",
               ssl_ca_certs="ca/cacert.pem")
   ```
   The `ssl_ca_certs` parameter makes uvicorn require and verify client certs.

3. **Configure Keycloak's script authenticator:**
   Update `keycloak/gateone-pqc-authenticator.js`:
   - Change `https://YOUR_GATEONE_HOST/verify-attestation` to `https://127.0.0.1:9899/verify-attestation`
   - Add client cert to the connection (Java's `SSLContext` with the client keystore)
   - Or simpler: run Keycloak's JVM with `-Djakarta.net.ssl.keyStore=...` pointing at a JKS containing `keycloak-client.crt` + `keycloak-client.key`

4. **Pin the CA:**
   ```bash
   make fingerprint
   ```
   Verify this SHA-384 matches on both the Keycloak host and the verifier host before trusting.

## What is still NOT production-ready

- **Endpoint authentication:** `/verify-attestation` has no bearer-token or API-key check. Anyone with a valid client cert can call it. Add a shared secret header check.
- **Real hostname:** `keycloak.conf` still has the hostname commented out. Set `hostname=https://auth.supergrok.ai` (or your real domain) before exposing beyond localhost.
- **Persistent sessions:** the Keycloak session store is an in-memory Map. Configure a database-backed store (Postgres/MySQL) for token revocation and audit continuity across restarts.
- **CRL/OCSP:** the CA config includes a CRL distribution point, but no OCSP responder is running. For 90-day certs this is acceptable; for longer-lived certs it is not.
- **Rate limiting:** the authenticator and verifier have no per-IP or per-node rate limits. Add them before any public exposure.
- **Audit log shipping:** the SCAR log and SovereignVault events are local files. Ship them to a central SIEM for tamper-evident retention.

## Security notes

- The CA private key (`ca/private/ca.key`) must have mode 600 and must never be committed to git. Add `ca/private/` to `.gitignore`.
- Leaf certs are 90 days: rotate with `make service` / `make client` before expiry. Automate with cron or a CI job.
- The previous 2048-bit RSA CA key and 20-year self-signed cert are retired. This setup uses P-384 + SHA-384 + 10-year CA + 90-day leaves, which meets NIST SP 800-57 guidance for new deployments.
- Dilithium (ML-DSA-87) remains the signature algorithm inside attestation tokens. mTLS protects the *transport*; Dilithium protects the *attestation payload*. Both are required.
