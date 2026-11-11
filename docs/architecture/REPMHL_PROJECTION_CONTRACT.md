# REPMHL Projection Contract

**Status:** Proposed architecture contract — owner approval required before load-bearing enforcement.  
**Target:** Sovereignty-AI-Studio  
**Baseline:** `7d4ee50649111854d4f940d1f9030943cd90d59c`  
**Authority:** SCAR remains the sole authoritative event history.

## 1. Decision boundary

REPMHL is specified here as a **read-optimized projection of verified SCAR rows**, not as a second independently authoritative hash chain.

This is a proposed decision, not an assertion that an implementation already exists. Appel420 (root owner) must approve this contract before REPMHL is treated as a production trust boundary.

```text
Authoritative event
      |
      v
 SCAR append + verification
      |
      +----> durable source record / receipt
      |
      v
 REPMHL projection worker
      |
      v
 read-optimized index / query surface

SCAR = authority       REPMHL = derived view
```

REPMHL MUST NOT create, mutate, reorder, or independently re-sign authoritative SCAR events. A REPMHL row is evidence of a projection operation, not a replacement for the source event or its receipt.

## 2. Source event requirements

A projection candidate MUST identify, at minimum:

- SCAR stream or ledger identity.
- Monotonic source sequence number.
- Source event identifier and event type.
- Canonical source event hash and hash algorithm/version.
- Source timestamp.
- Signature/key reference and the source verification result.
- Canonicalization/schema version needed to reproduce the source hash.

The projector MUST verify the source record and its authenticated receipt using the configured SCAR RootOfTrust interface before indexing it. A missing signer, invalid signature, unavailable trust root, malformed event, or hash mismatch MUST fail closed for that record. The projector MUST retain the reason and MUST NOT silently downgrade verification.

## 3. Projection row

A projection row MUST retain these source references:

| Field | Meaning |
|---|---|
| `source_ledger_id` | SCAR ledger identity |
| `source_sequence` | Original SCAR sequence |
| `source_event_id` | Original event identifier |
| `source_event_type` | Original event type |
| `source_event_hash` | Verified canonical source hash |
| `source_hash_algorithm` | Algorithm and version |
| `source_timestamp` | Original event time |
| `signature_reference` | Reference to SCAR signature/receipt |
| `signature_status` | Verification result, never a new REPMHL signature claim |
| `projection_schema_version` | REPMHL row schema version |
| `projected_at` | Projection processing time |

The row MAY contain indexed/searchable fields derived from the source event. Every derived field MUST be traceable to its source event and MUST NOT overwrite the preserved source references.

## 4. Ordering, cursor, and integrity rules

1. Process source records in SCAR sequence order within each ledger.
2. Verify the source event and receipt before writing its projection row.
3. Commit the row durably before advancing the projection cursor.
4. Advance the cursor only across a contiguous, verified sequence.
5. Treat a repeated source reference as an idempotency case only when the stored source hash is identical. A repeated reference with a different hash is an integrity failure.
6. Detect and report sequence gaps, out-of-order input, duplicate conflicts, hash mismatches, invalid signatures, and schema/canonicalization incompatibility.
7. Never advance past an unresolved gap merely to make the projection appear current.
8. Do not report a projection as complete when its source range is incomplete or unverified.

The cursor MUST identify the ledger and last contiguous verified sequence; it MUST NOT be a timestamp-only watermark.

## 5. Rebuild and recovery

A rebuild MUST replay the authoritative SCAR source from a declared starting sequence (normally the beginning or a verified checkpoint), re-verify each record, and reconstruct the projection deterministically.

A rebuild MUST record its source range, starting checkpoint, schema version, start/end times, result, and any rejected records. A rebuild MUST NOT rewrite SCAR history. If SCAR is unavailable or verification cannot complete, the projection remains unavailable/stale rather than claiming completeness.

Projection failure MUST NOT block a valid SCAR append. Conversely, a successful SCAR append MUST NOT be represented as a successful REPMHL update until the projection write is durable.

## 6. State model

Allowed externally visible projection states:

- `CURRENT`: contiguous projection through the declared SCAR high-water mark.
- `LAGGING`: valid projection exists, but its cursor trails the known SCAR high-water mark.
- `REBUILDING`: deterministic replay is in progress; completeness is not claimed.
- `INTEGRITY_FAILURE`: a verification, ordering, duplicate-conflict, or hash invariant failed.

Unknown state, missing cursor, or inability to establish the SCAR high-water mark MUST be treated as unavailable/unproven, not `CURRENT`.

## 7. Trust and signature boundary

The SCAR-injected RootOfTrust authenticates the authoritative SCAR receipt. REPMHL stores the signature reference and verification result. REPMHL MUST NOT claim that it independently signed, attested, or authenticated the source event.

A REPMHL storage checksum or index hash may protect local projection storage, but it MUST be labeled as projection integrity metadata and MUST NOT be confused with SCAR event authenticity.

## 8. Why projection rather than a second chain

An independent REPMHL chain would introduce a second authority boundary, signer lifecycle, sequence domain, fork/reconciliation policy, and dual-write failure modes. A SCAR projection keeps one authoritative history and makes REPMHL rebuildable.

The trade-off is explicit: REPMHL can lag or become unavailable while SCAR remains authoritative. Consumers MUST consult SCAR receipts for authoritative proof and MUST inspect projection state/cursor before relying on REPMHL query completeness.

## 9. Acceptance criteria

This contract is not implementation evidence. Before production approval, tests MUST demonstrate:

- valid sequential projection and cursor advancement;
- no cursor advance on failed verification or failed durable write;
- gap, reordering, duplicate-conflict, and hash-mismatch detection;
- invalid/missing signature and unavailable RootOfTrust fail-closed behavior;
- deterministic rebuild from SCAR;
- SCAR append availability during REPMHL outage;
- correct state transitions and explicit stale/unproven reporting;
- traceability from every projection row to its authoritative SCAR event.

**Approval gate:** owner approval of this projection architecture and its schema/versioning rules is required before load-bearing status.
