# Notification Delivery Contract

**Status:** Proposed delivery contract — thresholds and severity policy require owner approval before production enforcement.  
**Target:** Sovereignty-AI-Studio  
**Baseline:** `7d4ee50649111854d4f940d1f9030943cd90d59c`  
**Authority:** SCAR is the audit authority; notification delivery is a consumer workflow, not an authorization mechanism.

## 1. Purpose and invariants

This contract defines a verifiable notification pipeline for repository and CI events. It covers event grammar, webhook envelope, severity, delivery, retry, acknowledgement, and dead-man's-switch behavior.

Invariants:

- Notifications MUST NOT grant permissions or authorize repository actions.
- A webhook acknowledgement proves endpoint acceptance only; it does not prove that the owner read or understood the alert.
- Delivery state and owner-awareness state MUST remain distinct.
- Missing, malformed, unauthenticated, replayed, or uncorrelated events MUST fail closed and be recorded.
- No credential, access token, private key, session secret, or raw authorization header may appear in an event payload or audit record.

## 2. Event grammar

Canonical event types:

| Event type | Meaning | Default severity |
|---|---|---|
| `BRANCH_CREATED` | A branch was created | `INFO` |
| `PR_OPENED` | A pull request was opened | `INFO` |
| `PR_MERGED` | A pull request was merged | `WARNING` |
| `CI_PASSED` | A CI run completed successfully | `INFO` |
| `CI_FAILED` | A CI run failed or was cancelled in a policy-failing state | `CRITICAL` |

Severity values are `INFO`, `WARNING`, `ERROR`, and `CRITICAL`. The table gives proposed defaults. A policy may raise severity; it MUST NOT silently lower a critical integrity/security event. Event type and severity are separate fields.

A source adapter MUST map provider-specific event names and outcomes into this canonical grammar. Unknown event types MUST be quarantined and surfaced as unsupported; they MUST NOT be silently discarded or mapped to success.

## 3. Webhook envelope

The following JSON is the canonical envelope shape. Optional values may be null when the source does not provide them; required identity and integrity fields may not be omitted.

```json
{
  "schema_version": "1.0",
  "event_id": "uuid",
  "event_type": "CI_FAILED",
  "occurred_at": "2026-01-01T00:00:00Z",
  "severity": "CRITICAL",
  "source": {
    "system": "github",
    "repository": "owner/repository",
    "branch": "agent/example",
    "commit": "full_commit_sha"
  },
  "subject": {
    "pull_request": null,
    "workflow_run": {
      "id": "provider_run_id",
      "url": "https://github.com/owner/repository/actions/runs/provider_run_id",
      "conclusion": "failure"
    }
  },
  "evidence": {
    "scar_sequence": 123,
    "scar_event_hash": "hex_digest",
    "payload_hash": "hex_digest"
  },
  "delivery": {
    "attempt": 1,
    "idempotency_key": "stable-event-id"
  }
}
```

Field rules:

- `schema_version`: required, versioned contract identifier.
- `event_id`: required globally unique event identifier generated once and retained across retries.
- `event_type`: required canonical event type from Section 2.
- `occurred_at`: required UTC RFC 3339 timestamp from the source event.
- `severity`: required policy result.
- `source.system`, `source.repository`, `source.commit`: required source provenance; `branch` may be null when not applicable.
- `subject.pull_request` and `subject.workflow_run`: typed subject references; one or both may be null when not applicable.
- `evidence.scar_sequence`, `evidence.scar_event_hash`: required correlation to the authoritative SCAR event when SCAR has recorded it. If notification is queued before SCAR persistence, it MUST remain pending and MUST NOT be delivered as fully evidenced until correlation is established.
- `evidence.payload_hash`: hash of the canonical serialized event body, excluding transport headers and signature.
- `delivery.attempt`: one-based delivery attempt counter.
- `delivery.idempotency_key`: stable across retries; MUST resolve to the same logical event.

The example values are illustrative, not live evidence. URLs and identifiers MUST be derived from the actual provider event, never guessed.

## 4. Authentication, integrity, and replay protection

- Transport MUST use TLS with certificate validation.
- Each webhook MUST carry a cryptographic signature over the exact canonical payload bytes, using a configured signing key and documented algorithm/key identifier.
- The receiver MUST verify the signature before parsing the event as trusted input.
- A signed timestamp and bounded freshness window MUST be checked to reject stale delivery.
- The receiver MUST persist processed `event_id`/idempotency keys and suppress duplicate side effects.
- Key rotation MUST support an explicit overlap period and key identifier. Unknown, expired, or revoked keys MUST be rejected.
- Secrets MUST be stored outside payloads and logs. Signature material MUST never be logged.

## 5. Delivery semantics and retry

Delivery is **at least once**. Exactly-once network delivery is not promised.

- The sender MUST persist an event to a durable outbox before attempting delivery.
- Retry transient network failures, timeouts, HTTP 408, HTTP 429, and retryable 5xx responses using bounded exponential backoff with jitter and a maximum attempt/age policy.
- Do not retry permanent schema/authentication failures indefinitely; quarantine them and raise an operational alert.
- Honor valid `Retry-After` guidance.
- After retry exhaustion, retain the event in a durable dead-letter queue with the full non-secret delivery evidence.
- A receiver acknowledgement MUST include the event ID and a durable acceptance result. An HTTP success without event correlation is insufficient.
- Acknowledgement means accepted by the endpoint, not read by the owner.
- Recovery MUST replay dead-letter items under the same idempotency key and record the recovery result.

Every attempt records attempt number, destination identifier (not secret URL credentials), start/end time, transport result, response class, retry decision, and correlation ID.

## 6. Dead-man's switch and canary

The dead-man's switch MUST be operated by a watchdog independent of the notification endpoint it monitors. The monitored endpoint MUST NOT be the only mechanism capable of declaring its own failure.

Proposed initial thresholds (owner approval required):

- heartbeat expected every 60 seconds;
- `WARNING` after 2 consecutive missed heartbeat intervals;
- `CRITICAL` after 5 consecutive missed heartbeat intervals;
- synthetic canary event at least every 5 minutes;
- canary must traverse the same signing, queue, transport, receiver, and acknowledgement path as ordinary notifications.

The watchdog MUST distinguish a missed heartbeat from a confirmed endpoint failure. Clock skew, watchdog outage, and source pipeline outage MUST be separately represented. If the watchdog itself becomes unavailable, an independent supervisor or out-of-band health check MUST raise `MONITOR_UNAVAILABLE`; absence of watchdog output MUST never be interpreted as healthy.

Proposed operational states:

- `HEALTHY`
- `DEGRADED`
- `DELIVERY_FAILURE`
- `PIPELINE_FAILURE`
- `MONITOR_UNAVAILABLE`
- `CRITICAL_ESCALATION`

State transitions MUST be recorded with the triggering evidence, threshold, and timestamp. Recovery requires a successful end-to-end canary and a verified acknowledgement; merely restarting a process does not prove recovery.

## 7. SCAR audit grammar

The following SCAR event names are proposed for recording the notification lifecycle:

- `NOTIFICATION_EVENT_CREATED`
- `NOTIFICATION_DELIVERY_ATTEMPTED`
- `NOTIFICATION_DELIVERY_ACKNOWLEDGED`
- `NOTIFICATION_DELIVERY_FAILED`
- `NOTIFICATION_RETRY_SCHEDULED`
- `NOTIFICATION_HEARTBEAT_RECEIVED`
- `NOTIFICATION_HEARTBEAT_MISSED`
- `NOTIFICATION_CANARY_FAILED`
- `NOTIFICATION_PIPELINE_RECOVERED`

Each audit record SHOULD include the event ID, canonical event type, source repository/commit, severity, payload hash, destination identifier, attempt number, result, reason, and timestamp. SCAR sequence/hash references MUST be included when available. Secrets and raw authentication material MUST be excluded.

SCAR append failure MUST be surfaced as an audit-pipeline failure; the system MUST NOT claim an auditable delivery lifecycle when the corresponding audit record was not durably committed.

## 8. Failure behavior

| Failure | Required behavior |
|---|---|
| Invalid signature or stale timestamp | Reject; record security failure; no side effect |
| Duplicate event ID, same payload hash | Acknowledge as duplicate; no repeated side effect |
| Duplicate event ID, different payload hash | Integrity failure; quarantine and escalate |
| Receiver timeout/transient 5xx | Retry with bounded backoff |
| Retry exhaustion | Durable dead-letter; critical operational alert |
| Missing SCAR correlation | Hold pending; do not claim fully evidenced delivery |
| Missed heartbeat threshold | Dead-man escalation per approved policy |
| Canary not acknowledged | Delivery/pipeline failure; independent escalation |
| Watchdog unavailable | `MONITOR_UNAVAILABLE`; never report healthy |
| Owner has not acknowledged/read alert | Owner-awareness remains unknown/unacknowledged |

## 9. Acceptance criteria

Before production approval, tests MUST demonstrate:

- schema validation and rejection of unknown event types;
- signature verification, timestamp freshness, key rotation, and replay rejection;
- stable idempotency across retry and duplicate delivery;
- duplicate-ID/different-payload integrity escalation;
- bounded retry, jitter, Retry-After handling, and durable dead-letter recovery;
- explicit distinction between endpoint acknowledgement and owner awareness;
- heartbeat thresholds, canary path, watchdog independence, and watchdog-failure escalation;
- SCAR audit coverage for success, failure, retry, dead-letter, and recovery;
- no secrets in payloads or logs;
- end-to-end failure injection for endpoint outage and pipeline outage.

**Approval gate:** severity policy, heartbeat/canary thresholds, signing algorithm/key lifecycle, and event schema version must be approved by the owner before production enforcement.
