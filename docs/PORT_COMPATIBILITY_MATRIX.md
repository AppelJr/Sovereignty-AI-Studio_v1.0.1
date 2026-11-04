# Port Compatibility Matrix

This matrix separates implemented behavior from the endpoint list in the target port brief. Do not infer an endpoint from a port assignment.

| Service | Route / protocol | State | Notes |
|---|---|---|---|
| 9897 Python | GET /api/health | IMPLEMENTED | Read-only health via WebSocket server process_request |
| 9897 Python | GET /health | IMPLEMENTED | Same read-only health payload |
| 9897 Python | WebSocket / | IMPLEMENTED | handshake_ack, ai_chat, memory_query, memory_save, memory_get, token_op, ping, status |
| 9897 Python | HTTP /api/ai, /api/brain, /api/keys, /api/speak, /api/audit, /api/rotate-key, /api/conflicts | NOT IMPLEMENTED | Existing operations are not automatically equivalent to authenticated HTTP routes |
| 9898 Dashboard | GET / | IMPLEMENTED | Serves canonical dashboard HTML |
| 9898 Dashboard | GET /health | IMPLEMENTED | Dashboard health |
| 9898 Dashboard | GET /api/* | IMPLEMENTED | Fixed loopback proxy to 9899; no caller-controlled upstream |
| 9898 Dashboard | WebSocket /ws/ui | IMPLEMENTED | Read-only; rejects execution-shaped messages |
| 9898 Dashboard | POST /internal/events | IMPLEMENTED WITH TOKEN | Requires SG_DASHBOARD_EVENT_TOKEN of at least 32 bytes |
| 9899 Unified | GET /health | IMPLEMENTED | Node bridge health |
| 9899 Unified | GET /api/devassist420/provider-policy | IMPLEMENTED | Read-only policy view |
| 9899 Unified | GET /api/devassist/status | IMPLEMENTED | Trust/readiness status; may report blockers |
| 9899 Unified | /api/v1/* | EXISTING PROXY | Fixed FastAPI upstream from existing Node bridge configuration |
| 9899 Unified | WebSocket / and /ws/alerts | EXISTING | Node bridge channels |
| 8080 / 8443 | Keycloak | CONFIGURED PORTS; DEVICE CHECK PENDING | HTTP / HTTPS identity provider |
| 6379 / 5432 | Redis / PostgreSQL | INTERNAL ONLY | Never publish host-facing listeners |

## Known voice contract mismatches

- Frontend voice input reads processing.response and processing.audio_file.
- Current voice interaction service emits response_text and audio_path.
- Current voice interaction service constructs an audio path without proving a WAV file was generated.
- The browser requires an HTTP-accessible audio URL, not a server filesystem path.
- Local STT, local model inference and Piper playback have not yet passed one end-to-end device test.

These are M1 blockers, not green capabilities.
