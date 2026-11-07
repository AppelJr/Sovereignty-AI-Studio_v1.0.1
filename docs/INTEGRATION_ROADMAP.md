# Sovereignty AI Studio — Integration Roadmap

Status is evidence-based. A green CI check is not a device-runtime or production-security attestation.

## M0 — Canonical service and port ownership

**State: IMPLEMENTED IN DRAFT PR; CI PASS; DEVICE TEST PENDING**

- 9897: Python WebSocket bridge with read-only HTTP health at /api/health and /health.
- 9898: Dashboard server, read-only UI WebSocket, static allowlist, and fixed loopback /api proxy.
- 9899: Existing Unified Node / DevAssist relay under canonical Unified_Server.js entrypoint.
- 8080 / 8443: Keycloak HTTP / HTTPS.
- 6379 / 5432: Redis / PostgreSQL internal Docker services only.
- Loopback bind enforcement, duplicate-port checks, safe static file resolution, and compatibility aliases.
- Draft PR #187 targets protected Collaboration.

**Exit evidence:** all native runtime, syntax, Node, Python health-contract and static security gates pass; device live test reports 9897, 9898 and 9899 PASS.

## M1 — Local voice interoperability

**State: BLOCKED / PARTIAL — NEXT IMPLEMENTATION LANE**

Current source evidence identifies these defects or missing connections:

- recordLocalAudio() immediately stops after starting; the controller API is the valid lifecycle.
- The voice input UI expects processing.response and processing.audio_file; the backend service currently emits response_text and audio_path.
- Voice interaction currently returns an audio path without proving that a WAV file was generated or made available to the browser.
- The offline-first response implementation can return an acknowledgement rather than a local-model inference result.
- Piper exists as a service, but the complete STT → local model → Piper → browser playback path is not proven.
- ChatGPT's private built-in Voice runtime isn't exposed for direct audio-stream control. Integration must use user-mediated session checkpoints and supported events.

**Work sequence:**

1. Normalize one versioned VoiceTurn schema across frontend, FastAPI, Python bridge and Node relay.
2. Keep microphone capture lifecycle explicit: start → capture → stop → bounded upload → STT result; cancellation must discard partial audio.
3. Generate Piper audio into a managed local output directory; serve it by opaque ID through a loopback-only, authorization-checked route. Never return filesystem paths as browser URLs.
4. Use the shared synchronization contract for lane IDs, turn IDs, sequence numbers, event digests, provenance and audio-resource leases.
5. Permit parallel text/model processing, but enforce one microphone capture and one speaker playback lease at a time.
6. Test no echo, duplicate turn, replay, cross-lane leakage, missing Piper, missing STT and cancellation.

**Exit evidence:** real device microphone test, local STT transcript, local-model response, Piper audio playback, exclusive speaker lease, and a complete SCAR event chain. Remote fallback remains disabled.

## M2 — Shared synchronization and memory continuity

**State: REFERENCE CONTRACT PASS; REPOSITORY ADAPTERS NOT CONNECTED**

- Port the standalone synchronization contract into the repository with production signature verification.
- Bind session ID, owner device, lane ID, policy epoch, sequence and event digest.
- Use idempotent append-only event ingestion and explicit conflict resolution by the owner.
- Connect the local canonical memory store and checkpoint export.
- Add encrypted GitHub replication only as an explicitly authorized backup path; local state remains primary.
- Do not call a hash chain physically immutable without independent anchoring and tamper-resistant storage.

**Exit evidence:** multi-lane concurrency, replay rejection, stale-policy rejection, signed event verification, restore test and independently verifiable audit checkpoint.

## M3 — GateOne identity and policy

**State: NOT PROMOTED**

- Keycloak identity at 8080/8443.
- Bind person + device + request + policy authorization; biometric presence alone is insufficient.
- GateOne trust evaluation, RBAC and capability checks.
- PQC attestation and key lifecycle, revocation and rollback tests.
- Council and model outputs remain proposals; only the owner-authorized policy engine grants capabilities.
- No provider key or bearer secret in SCAR records.

**Exit evidence:** negative authorization tests, identity mismatch tests, revocation tests, signature-verification tests and owner approval.

## M4 — Library and repository consolidation

**State: INVENTORY CREATED; ORIGINALS PRESERVED**

- Deduplicate by content hash, not filename or branch-prefix depth.
- Classify artifacts as canonical, active, historical, duplicate, conflicting, sensitive or unresolved.
- Preserve original artifacts and provenance.
- Resolve version drift and unique branch commits using agent branches and PRs; never force-update Collaboration.
- Treat GitHub dynamic startup failures separately from source-controlled YAML workflows.

**Exit evidence:** signed inventory, duplicate report, unresolved-conflict register and approved retention/deletion decisions.

## M5 — Interactive live verification and release

**State: HARNESS IMPLEMENTED; DEVICE EXECUTION PENDING**

Run the interactive read-only test with:

    npm run test:live

Required release gates:

- 9897 HTTP health and WebSocket handshake/ping: PASS.
- 9898 dashboard, same-origin API proxy and read-only UI WebSocket: PASS.
- 9899 health and WebSocket relay: PASS.
- Keycloak 8080/8443: PASS for production SSO; otherwise release remains identity-blocked.
- Redis/PostgreSQL remain internal-only.
- Voice path and synchronization adapter pass on the iPhone/iSH runtime.
- CI, security, dependency and branch-protection checks are current.
- Human owner reviews the playground and explicitly approves promotion.

No PR is merged and no production deployment occurs automatically.
