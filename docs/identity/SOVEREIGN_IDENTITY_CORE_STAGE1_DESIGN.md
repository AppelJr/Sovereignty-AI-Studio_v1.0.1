# Sovereignty Identity Core — Stage 1 Design and Test Plan

Status: ACCEPTED ARCHITECTURE BASELINE / DESIGN ONLY  
Implementation status: NOT IMPLEMENTED  
Production status: BLOCKED

## 1. Authority invariants

1. The human owner root is the sole source of owner authority.
2. Device identity proves possession of an enrolled device key; it does not independently prove human intent.
3. External SAML assertions, OIDC ID tokens, OAuth access tokens, SCIM records, and upstream group memberships are federation inputs only.
4. No federation input may create, replace, elevate, or recover the owner root.
5. Gate.One remains the independent authorization boundary. Authentication and federation do not imply authorization.
6. Identity Core does not execute actions. It emits verified identity and device claims for Gate.One policy evaluation.
7. Every enrollment, trust-anchor change, revocation, and verification failure emits attributable SCAR evidence.
8. No protocol adapter inherits owner authority.

## 2. Stage 1 component boundaries

Owner Root Authority
- Owner-controlled enrollment ceremony and recovery policy.
- Explicit distinction between owner identity, device identity, and service identity.
- No external IdP may enroll or rotate the owner root.

Identity Registry
- Stable opaque subject identifier.
- Identity status: PENDING, ACTIVE, SUSPENDED, REVOKED.
- Separate principal types: OWNER, HUMAN, DEVICE, SERVICE, FEDERATION_PARTNER.
- External issuer/subject pairs are aliases, never canonical owner identifiers.
- Registry mutations require a Gate.One authorization decision and SCAR receipt.

Device Enrollment
- Device-generated key pair; private key remains on the device.
- Enrollment challenge binds owner subject, device public-key fingerprint, requested capabilities, expiry, and nonce.
- Owner approval is required before ACTIVE status.
- Device revocation invalidates future proof verification and session renewal.
- Hardware-backed key storage is preferred when supported; software fallback must be explicitly marked lower assurance.

Trust Anchor Registry
- Versioned, append-only trust-anchor records.
- Each record binds anchor ID, purpose, issuer, key/certificate fingerprint, validity window, status, and rotation predecessor.
- SAML signing certificates and OIDC issuer/JWKS keys are partner trust anchors, not owner roots.
- Trust-anchor updates require owner-authorized change approval and independent evidence.

## 3. Data model (logical)

IdentityRecord
- subject_id, principal_type, status, created_at, updated_at
- owner_root_ref (nullable except owner principal)
- assurance_level, attributes_hash, registry_version

DeviceRecord
- device_id, subject_id, public_key_fingerprint, key_algorithm
- attestation_ref, enrollment_status, enrolled_at, revoked_at
- assurance_level, last_seen_at

TrustAnchorRecord
- anchor_id, purpose, issuer, key_fingerprint, algorithm
- not_before, not_after, status, version, predecessor_anchor_id
- approved_by_owner_proof_id, scar_event_id

FederationAlias
- partner_id, protocol, issuer, external_subject, canonical_subject_id
- mapping_status, created_at, last_verified_at
- Must never contain an owner-authority flag or Gate.One permission grant.

## 4. Trust and authorization flow

External assertion / SCIM event
        |
        v
Protocol-specific validation (future stages)
        |
        v
Federation alias resolution
        |
        v
Identity Core subject lookup
        |
        v
Device proof / enrollment status (when device-bound)
        |
        v
Verified identity context
        |
        v
Gate.One policy evaluation
        |
        +---- DENY / REQUIRE_CONFIRMATION / ALLOW_WITH_APPROVAL
        |
        v
SCAR evidence
        |
        v
Protected application

The Identity Core output is identity evidence only. Gate.One alone makes the authorization decision.

## 5. Stage 1 acceptance criteria

- An external SAML assertion cannot create an OWNER principal.
- An OIDC ID token with owner-like claims cannot elevate a HUMAN or SERVICE principal to OWNER.
- An OAuth access token cannot be interpreted as an identity credential or owner proof.
- A SCIM create/update/group event cannot assign owner authority.
- Duplicate enrollment challenges are rejected (nonce replay).
- Expired, revoked, mismatched-owner, and mismatched-device proofs are rejected.
- A device cannot enroll itself as owner without owner approval.
- Trust-anchor replacement cannot occur without an owner-authorized change proof.
- Registry and trust-anchor changes fail closed if SCAR persistence fails.
- Identity verification never returns Gate.One ALLOW by itself.

## 6. Negative and adversarial test plan

| Test | Attack / condition | Expected result |
|---|---|---|
| ID-001 | SAML NameID maps to owner alias without owner proof | DENY |
| ID-002 | OIDC token contains owner=true / admin=true claims | DENY elevation |
| ID-003 | OAuth access token presented as owner identity | DENY |
| ID-004 | SCIM group maps to owner/admin | DENY elevation |
| ID-005 | Device enrollment without owner approval | PENDING / DENY |
| ID-006 | Replayed enrollment nonce | DENY |
| ID-007 | Expired device proof | DENY |
| ID-008 | Revoked device key | DENY |
| ID-009 | Device proof bound to another owner | DENY |
| ID-010 | Trust-anchor rotation without owner proof | DENY |
| ID-011 | SCAR append unavailable during registry mutation | ABORT / DENY |
| ID-012 | Federation issuer unknown or untrusted | DENY |
| ID-013 | Valid federated identity requests protected action | Gate.One decision required |
| ID-014 | Federation alias collision across issuers | QUARANTINE / DENY |
| ID-015 | External provider requests owner-root recovery | DENY |

## 7. Required evidence contract

Each security-relevant event records:
who, what, when, where, why, how, authorization, memory_loaded,
network_accessed, files_changed, result, subject_id, device_id,
trust_anchor_id, registry_version, event_id, and prior_event_hash.

Evidence records must not contain private keys, bearer tokens, SAML assertions,
OIDC ID tokens, OAuth access/refresh tokens, or raw SCIM secrets.

## 8. Explicit non-goals for Stage 1

- No OAuth 2.0 or OIDC server implementation.
- No SAML IdP/SP implementation.
- No SCIM endpoint implementation.
- No Keycloak deletion or replacement.
- No production enrollment or key ceremony.
- No FIPS, SOC 2, ISO 27001, or protocol-conformance claim.

Those are later stages and require separate acceptance.

## 9. Stage 1 verification gate

Required before implementation approval:
1. Owner-root threat model review.
2. Identity/device/federation principal separation review.
3. Schema and state-transition review.
4. Negative-test plan approval.
5. SCAR evidence contract review.

Current result: DESIGN ARTIFACT ONLY — implementation and tests NOT RUN.
