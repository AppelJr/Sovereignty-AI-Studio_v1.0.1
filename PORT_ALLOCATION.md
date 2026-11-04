# Port Architecture

The canonical service definitions and security boundaries are maintained in docs/PORT_ARCHITECTURE.md.

| Port | Service | Canonical entrypoint |
|---:|---|---|
| 9897 | Python Bridge — AI, memory, key lifecycle, audit, STT/TTS | python3_bridge.py |
| 9898 | Frontend / Dashboard — HTML, UI WebSocket, same-origin API proxy | server_9898.js |
| 9899 | Unified Node REST / WebSocket relay | Unified_Server.js |
| 8080 | Keycloak HTTP | Keycloak |
| 8443 | Keycloak HTTPS | Keycloak |
| 6379 | Redis — internal Docker network only | Docker |
| 5432 | PostgreSQL — internal Docker network only | Docker |

The dashboard proxies only /api/* to the fixed loopback Unified Server on port 9899. The UI WebSocket at /ws/ui is a read-only event channel. No browser event grants authorization or executes a protected action.

Start the canonical application services with:

    ./START_SERVER.sh

Open the dashboard at:

    http://127.0.0.1:9898/

Do not start legacy server aliases alongside the canonical entry points; that would create port collisions and split runtime ownership.
