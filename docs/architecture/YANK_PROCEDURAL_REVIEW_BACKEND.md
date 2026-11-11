# Bounded YANK Procedural Review — Backend Contract

## Status

Implementation branch: agent/yank-procedural-review-20261110

The backend service implements the bounded procedural-review state machine. It is
not a second arbitration authority and it does not grant release authorization.

## State transitions

| Current state | Operation | Guard | Next state |
|---|---|---|---|
| ESCROWED | File challenge | Verified participant; challenger is not any original YANK initiator; one challenge only | CHALLENGE_FILED |
| CHALLENGE_FILED | Complete review | Independent authorized reviewer; one review only | READY_FOR_RERUN or HELD_FOR_HUMAN_ESCALATION |
| READY_FOR_RERUN | Start rerun | Substantiated finding; Gate authorization revalidated; rerun count is zero | RERUN_IN_PROGRESS |
| RERUN_IN_PROGRESS | Finish rerun | Exactly one persisted rerun attempt | RESOLVED for PASS, otherwise HELD_FOR_HUMAN_ESCALATION |
| Any other state | Challenge/review/rerun | Invalid transition | DENY |

The permitted defect categories are:

- OMITTED_EVIDENCE
- MISAPPLIED_CRITERIA
- CONFLICT_OF_INTEREST

The review examines only the cited procedural defect. It does not reconsider
the substantive merits or replace the original Council/Heavy Judge criteria.

## Persistence and evidence

- State is stored in a file-backed SQLite database.
- SQLite uses WAL mode, FULL synchronous writes, foreign-key enforcement, and
  BEGIN IMMEDIATE for state transitions.
- Challenge, review, rerun, and SCAR receipt rows reject SQL UPDATE and DELETE.
- Every transition appends a signed SCAR event before its SQLite transaction
  commits. If the SCAR sink fails or returns an invalid receipt, the state
  transaction rolls back.
- A persisted RERUN_IN_PROGRESS state consumes the single rerun budget before
  the external rerun handler is called. A process crash therefore does not
  silently permit a second rerun; recovery requires human escalation.
- Evidence stores references and digests, not candidate text, credentials,
  session keys, or raw private payloads.

Important limitation: the repository's current SCARLedger implementation is
process-memory-only. Persisting its signed append receipt in this SQLite store
does not make the canonical SCAR ledger itself durable across process restarts,
nor does it independently verify or anchor the root-of-trust signature.
Production deployment must bind a durable SCAR sink and verify its signature
and retention policy.

## Required backend bindings

The service requires four injected dependencies:

1. evidence_sink — the canonical SCAR append adapter. It must return an object
   with event_type, event_id, event_hash, signature, and sequence.
2. participant_check(challenger_id, arbitration_id) — checks the trusted
   participant registry.
3. reviewer_check(reviewer_id, arbitration_id, challenger_id, initiator_ids) —
   checks reviewer authorization and independence.
4. rerun_authorizer(requester_id, arbitration_id, task_id) — revalidates the
   original Gate proof, owner, task, scope, policy, decision, and expiry.

HTTP handlers must derive challenger_id, reviewer_id, and requester_id from
authenticated server-side principals. They must never accept those identities
as authoritative request-body fields.

## Integration contract

When the original arbitration returns YANK, trusted orchestration code must:

1. Preserve the original task ID and candidate SHA3-512 digest.
2. Resolve all actual YANK initiator identities from trusted verdict provenance.
3. Call create_yank_arbitration with a unique arbitration ID.
4. Keep the candidate output withheld.

An authenticated participant may then file one challenge with a specific defect
category, a concise explanation, and opaque evidence references. A separately
authorized reviewer records SUBSTANTIATED or NOT_SUBSTANTIATED with rationale
and evidence references.

Only SUBSTANTIATED permits one rerun. The rerun handler receives the original
arbitration/task binding and review evidence. Its PASS result records RESOLVED,
but output_released remains false. Any actual output release must still pass
the existing Gate 2 exact-candidate and evidence-acknowledgment boundary.

## API exposure boundary

This patch adds the backend policy service and focused tests. It does not add
HTTP routes because the inspected branch does not expose an authenticated
principal/router contract for these operations. Adding public routes without
that identity boundary would allow client-supplied actor IDs to impersonate
participants or reviewers. Route integration must bind to the existing
authenticated session and canonical Gate/participant registry.

## Validation record

The focused service tests exercise initiator rejection, participant rejection,
defect/evidence validation, one-challenge limit, reviewer independence,
unsubstantiated hold, Gate-gated rerun, single-rerun enforcement, rerun failure,
SCAR failure rollback, state persistence across service reopen, immutable
receipt rows, and duplicate arbitration registration.

Full repository regression, live API integration, durable SCAR integration,
device runtime, and production deployment are separate NOT RUN / NOT VERIFIED
gates until executed in the repository environment.
