#!/usr/bin/env bash
# Sovereignty AI Studio — canonical three-service local runtime.
set -Eeuo pipefail
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
NODE_BIN="${NODE_BIN:-node}"
PY_PORT="${SG_PORT:-9897}"
DASHBOARD_PORT="${PORT:-${STATIC_PORT:-9898}}"
UNIFIED_PORT="${PORT_UNIFIED:-${NODE_BRIDGE_PORT:-9899}}"
NETWORK_MODE="${SG_NETWORK_MODE:-local}"
REMOTE_NETWORK_ENABLED="${SG_ENABLE_REMOTE_NETWORK:-0}"
LOCAL_ALLOWLIST="${SG_LOCAL_NETWORK_ALLOWLIST:-}"
case "$NETWORK_MODE" in
  local|offline)
    NETWORK_MODE="local"
    REMOTE_NETWORK_ENABLED="0"
    ;;
  hybrid)
    if [[ -z "${LOCAL_ALLOWLIST//[[:space:]]/}" ]]; then
      echo "Refusing HYBRID startup: SG_LOCAL_NETWORK_ALLOWLIST must contain at least one approved host." >&2
      exit 1
    fi
    REMOTE_NETWORK_ENABLED="0"
    ;;
  online)
    if [[ "$REMOTE_NETWORK_ENABLED" != "1" ]]; then
      echo "Refusing ONLINE startup: set SG_ENABLE_REMOTE_NETWORK=1 through deployment-owner policy." >&2
      exit 1
    fi
    ;;
  *)
    echo "Refusing startup: SG_NETWORK_MODE must be local, hybrid, or online (got $NETWORK_MODE)." >&2
    exit 1
    ;;
esac
for port in "$PY_PORT" "$DASHBOARD_PORT" "$UNIFIED_PORT"; do
  [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || { echo "Invalid service port: $port" >&2; exit 1; }
done
if [[ "$PY_PORT" == "$DASHBOARD_PORT" || "$PY_PORT" == "$UNIFIED_PORT" || "$DASHBOARD_PORT" == "$UNIFIED_PORT" ]]; then
  echo "Refusing duplicate service port assignments." >&2
  exit 1
fi
[[ -x "$PYTHON_BIN" ]] || { echo "Missing local Python runtime: $PYTHON_BIN. Run ./INSTALL.sh first." >&2; exit 1; }
[[ -f "$ROOT_DIR/python3_bridge.py" ]] || { echo "Missing Python bridge entrypoint." >&2; exit 1; }
[[ -f "$ROOT_DIR/server_9898.js" ]] || { echo "Missing dashboard entrypoint server_9898.js." >&2; exit 1; }
[[ -f "$ROOT_DIR/Unified_Server.js" ]] || { echo "Missing unified Node entrypoint Unified_Server.js." >&2; exit 1; }
[[ -f "$ROOT_DIR/node-bridge/devassist420-preload.js" ]] || { echo "Missing DevAssist420 preload." >&2; exit 1; }
[[ -d "$ROOT_DIR/node_modules/ws" ]] || { echo "Missing root ws dependency. Run npm ci." >&2; exit 1; }
[[ -d "$ROOT_DIR/node-bridge/node_modules/express" || -d "$ROOT_DIR/node_modules/express" ]] || { echo "Missing Node bridge dependencies. Run npm ci --prefix node-bridge." >&2; exit 1; }
"$ROOT_DIR/scripts/diamond-core-runtime-gate.sh"
"$PYTHON_BIN" - "$PY_PORT" "$DASHBOARD_PORT" "$UNIFIED_PORT" <<'PY'
import socket
import sys

for raw in sys.argv[1:]:
    port = int(raw)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError as exc:
        raise SystemExit(f"Port {port} is unavailable; refusing partial startup: {exc}")
    finally:
        sock.close()
PY
export PIPER_MODEL="${PIPER_MODEL:-$ROOT_DIR/models/en_US-lessac-medium.onnx}"
export PIPER_DIR="${PIPER_DIR:-$ROOT_DIR/piper-tts}"
export SG_NETWORK_MODE="$([[ "$NETWORK_MODE" == "local" ]] && echo offline || echo "$NETWORK_MODE")"
export SG_LOCAL_NETWORK_ALLOWLIST="$LOCAL_ALLOWLIST"
export SG_HOST="127.0.0.1"
export DASHBOARD_HOST="127.0.0.1"
export UNIFIED_HOST="127.0.0.1"
export NODE_BRIDGE_HOST="127.0.0.1"
export SG_DEVICE_MODE="${SG_DEVICE_MODE:-ghost}"
export SG_ENABLE_REMOTE_NETWORK="$REMOTE_NETWORK_ENABLED"
export SG_ALLOW_BACKGROUND_POLLING="0"
export SG_ENABLE_WEBSOCKET="${SG_ENABLE_WEBSOCKET:-0}"
export SG_ENABLE_SSE="${SG_ENABLE_SSE:-0}"
export SG_RUNTIME_OWNER="DevAssist420SGHv119.html"
export SOVEREIGN_STATE_PATH="${SOVEREIGN_STATE_PATH:-$ROOT_DIR/state/canonical.json}"
export SCAR_PATH="${SCAR_PATH:-$ROOT_DIR/AUDIT/devassist-device.jsonl}"
export CORS_ORIGIN="${CORS_ORIGIN:-http://127.0.0.1:$DASHBOARD_PORT}"
pids=()
cleanup() {
  trap - EXIT INT TERM
  echo "Stopping canonical local services..."
  for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]:-}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM
SG_PORT="$PY_PORT" SG_HOST=127.0.0.1 SG_NETWORK_MODE="$NETWORK_MODE" SG_DEVICE_MODE="$SG_DEVICE_MODE" SG_ENABLE_REMOTE_NETWORK="$SG_ENABLE_REMOTE_NETWORK" SG_ALLOW_BACKGROUND_POLLING="$SG_ALLOW_BACKGROUND_POLLING" SG_ENABLE_WEBSOCKET="$SG_ENABLE_WEBSOCKET" SG_ENABLE_SSE="$SG_ENABLE_SSE" "$PYTHON_BIN" "$ROOT_DIR/python3_bridge.py" &
pids+=("$!")
PORT_UNIFIED="$UNIFIED_PORT" NODE_BRIDGE_PORT="$UNIFIED_PORT" UNIFIED_HOST=127.0.0.1 SG_BRIDGE_HTTP_URL="http://127.0.0.1:$PY_PORT" CORS_ORIGIN="$CORS_ORIGIN" SG_NETWORK_MODE="$NETWORK_MODE" SG_DEVICE_MODE="$SG_DEVICE_MODE" SG_ENABLE_REMOTE_NETWORK="$SG_ENABLE_REMOTE_NETWORK" SG_ALLOW_BACKGROUND_POLLING="$SG_ALLOW_BACKGROUND_POLLING" SG_ENABLE_WEBSOCKET="$SG_ENABLE_WEBSOCKET" SG_ENABLE_SSE="$SG_ENABLE_SSE" "$NODE_BIN" "$ROOT_DIR/Unified_Server.js" &
pids+=("$!")
PORT="$DASHBOARD_PORT" PORT_UNIFIED="$UNIFIED_PORT" DASHBOARD_HOST=127.0.0.1 "$NODE_BIN" "$ROOT_DIR/server_9898.js" &
pids+=("$!")
echo "Canonical Sovereignty AI Studio runtime running:"
echo "  Python:    ws://127.0.0.1:$PY_PORT"
echo "  Dashboard: http://127.0.0.1:$DASHBOARD_PORT/"
echo "  Unified:   http://127.0.0.1:$UNIFIED_PORT"
echo "  UI WS:     ws://127.0.0.1:$DASHBOARD_PORT/ws/ui"
echo "  DevAssist: http://127.0.0.1:$UNIFIED_PORT/api/devassist/status"
echo "  mode:      $SG_DEVICE_MODE / $NETWORK_MODE"
if [[ "$NETWORK_MODE" == "hybrid" ]]; then echo "  network:   allowlist-gated"; fi
if [[ "$NETWORK_MODE" == "online" ]]; then echo "  network:   explicitly enabled"; fi
echo "  diamond:   PASS (startup admitted)"
echo "Press Ctrl+C to stop."
wait -n "${pids[@]}"
exit $?
