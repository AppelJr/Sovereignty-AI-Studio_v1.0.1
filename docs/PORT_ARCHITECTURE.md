# Sovereignty AI Studio — Canonical Port Architecture

## Runtime contract

The runtime has three application-facing services. Port ownership is exclusive; do not start a second server on an assigned port.

| Port | Canonical entrypoint | Service | Responsibility |
|---:|---|---|---|
| 9897 | python3_bridge.py | Python Bridge | AI inference adapters, local brain/memory, key lifecycle, audit, STT/TTS and backend WebSocket |
| 9898 | server_9898.js | Frontend / Dashboard | SGHv119 HTML/assets, UI WebSocket bus, health, same-origin /api proxy to 9899 |
| 9899 | Unified_Server.js | Unified Node Server | REST API relay, WebSocket relay, DevAssist420 authorization boundary, FastAPI/Docker bridge |

## Traffic map

    iOS / iSH / macOS -------------> 9897 Python Bridge
              |
              +-- Browser ----------> 9898 Dashboard
              |                       +-- HTML / static assets
              |                       +-- /ws/ui (read-only UI event bus)
              |                       +-- /api/* ------------------+
              |                                                     |
              +-- API / WS clients ------------------------------> 9899 Unified Node
                                                                    +-- DevAssist420
                                                                    +-- REST / WS relay
                                                                    +-- FastAPI / Docker upstreams

    Keycloak: 8080 HTTP / 8443 HTTPS
    Redis:    6379 (internal Docker network only)
    Postgres: 5432 (internal Docker network only)

## Service responsibilities

### 9897 — Python Bridge

- Entry point: python3_bridge.py
- Default bind: 127.0.0.1
- Backend AI and local inference transport
- Brain/memory operations and session continuity
- Key rotation and audit events
- STT/TTS integration, including local Piper
- HTTP health compatibility at GET /api/health and /health; WebSocket message operations remain the current AI/memory/token interface

### 9898 — Frontend / Dashboard

- Entry point: server_9898.js
- Default bind: 127.0.0.1
- Serves DevAssist420SGHv119.html as the root dashboard
- Serves allowlisted web assets only; private state, keys, logs, models and repository internals are not web content
- GET /health reports dashboard health
- /ws/ui is a read-only event channel; it cannot authorize or execute work
- /api/* is proxied only to the fixed loopback Unified Server on 9899
- Internal event publication requires a 32-byte-or-longer SG_DASHBOARD_EVENT_TOKEN

### 9899 — Unified Node Server

- Entry point: Unified_Server.js
- Default bind: 127.0.0.1
- REST API and WebSocket relay
- DevAssist420 policy, authorization and execution boundary
- Connects to Python WebSocket at 9897
- Browser-originated requests retain owner-session proof headers through the 9898 same-origin proxy

### Identity and internal data services

- Keycloak HTTP: 8080
- Keycloak HTTPS: 8443
- Redis: 6379, internal Docker network only
- PostgreSQL: 5432, internal Docker network only
- Redis and PostgreSQL must not be published on public interfaces.

## Environment variables

| Variable | Default | Purpose |
|---|---:|---|
| SG_PORT | 9897 | Python Bridge |
| PORT | 9898 | Dashboard HTTP |
| PORT_UNIFIED | 9899 | Unified Node Server |
| NODE_BRIDGE_PORT | 9899 | Backward-compatible alias |
| DASHBOARD_HOST | 127.0.0.1 | Dashboard bind |
| UNIFIED_HOST | 127.0.0.1 | Unified Server bind |
| KEYCLOAK_URL | http://127.0.0.1:8080 | Keycloak base URL |
| SG_DASHBOARD_EVENT_TOKEN | unset | Authenticates internal UI-event publication |

## Startup and health checks

Start all three application services:

    ./START_SERVER.sh

Check each service independently:

    curl --fail http://127.0.0.1:9898/health
    curl --fail http://127.0.0.1:9899/health
    curl --fail http://127.0.0.1:9899/api/devassist/status

Dashboard URL:

    http://127.0.0.1:9898/

Python WebSocket:

    ws://127.0.0.1:9897

Dashboard UI event WebSocket:

    ws://127.0.0.1:9898/ws/ui

Unified Node WebSocket:

    ws://127.0.0.1:9899/

## Security invariants

1. Each service has one canonical entry point and one assigned application port.
2. All standalone application services bind to loopback by default.
3. Dashboard /api forwarding targets only loopback port 9899; clients cannot select an upstream host.
4. Dashboard UI WebSocket is read-only. It cannot execute commands or grant capabilities.
5. Owner-session proof is forwarded unchanged to the authorization boundary.
6. The dashboard never serves state, audit ledgers, secrets, key material, model files or repository internals.
7. Redis and PostgreSQL remain internal to Docker.
8. A missing service is reported as unavailable; no alternate port or remote fallback is silently selected.
9. Keycloak identity is not inferred from a browser label or voice.
10. Orchestrator and dashboard are not authorization authorities.

## REST compatibility status

The Python bridge currently exposes GET /api/health and /health over the same listener as its WebSocket service. Existing AI, memory, and token operations remain on the established WebSocket message protocol. The following HTTP routes from the target architecture are not yet proven or exposed on 9897 and must remain marked NOT IMPLEMENTED until their authorization and audit adapters are wired: /api/ai, /api/keys, /api/speak, /api/audit, /api/rotate-key, and /api/conflicts. Do not create unauthenticated HTTP mutation aliases for these operations.
