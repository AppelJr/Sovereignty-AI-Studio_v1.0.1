# v1.0.2 — Local OAuth Credential Generator

**Status: local-first, CI-verified. Not production-ready for corporations.**

## What this release ships

- **OAuth local generator** (`scripts/oauth_local_generator.py`): Ed25519 key generation with deterministic kid derivation, writes three artifacts (oauth-client.json, oauth-private-key.pem, provenance.json) with O_EXCL flags and 0600 permissions.
- **Contract validator** (`scripts/validate-local-oauth.py`): asserts issuer is "local", external OAuth disabled, network access false.
- **Security tests** (`tests/test_oauth_local_generator_security.py`): verify no private key leaks into client metadata, no network access, provenance event recorded.
- **CI workflow** (`.github/workflows/sovereign-oauth-generator.yml`): lean lane — native git checkout, pip install cryptography, run generator, assert artifacts. No third-party actions.
- **Policy file** (`config/local-oauth-policy.json`): canonical declaration of issuer, generator path, network_access false, external_oauth disabled.
- **Documentation** (`docs/LOCAL_OAUTH_AND_EXTERNAL_INTEGRATIONS.md`): explains the local issuer is Ed25519-based, makes no network calls, and external OAuth is disabled by policy.

## What this release does NOT ship

- No live authorization server.
- No consent flow.
- No token exchange.
- No registration with any external provider (Google, Auth0, etc.).
- No rate limiting, no global infrastructure.

The generator mints **local credentials** that validate against nothing outside this repository. A corporation cannot authenticate users with these keys.

## Honest framing

This is a working local credential minting tool with CI-verified provenance logging. The green CI checks prove the script runs and passes its own tests. They do not prove the system authenticates anyone at scale.

## Attribution

- Generator script, validator, security tests, and CI workflow: authored in the Grok lane at AppelJr's direction (provenance note in workflow file, rewritten 2026-10-08).
- Repository owner and release publisher: AppelJr.
- This release notes file: drafted by Grok lane, committed by AppelJr.

## Tag

Use tag **v1.0.2** (hyphenated, no spaces, no colons). Do not use a tag containing a claim like "production live enterprise grade" — that claim is false and would be false advertisement on a public release page.
