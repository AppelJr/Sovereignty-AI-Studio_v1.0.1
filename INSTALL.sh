#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
OFFLINE=0
if [[ "${1:-}" == "--offline" ]]; then OFFLINE=1
elif [[ $# -ne 0 ]]; then echo "Usage: $0 [--offline]" >&2; exit 64; fi
command -v "$PYTHON_BIN" >/dev/null 2>&1 || { echo "ERROR: Python 3.11 or newer is required." >&2; exit 1; }
command -v node >/dev/null 2>&1 || { echo "ERROR: Node.js 24 or newer is required." >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "ERROR: npm is required with Node.js 24 or newer." >&2; exit 1; }
"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("ERROR: Python 3.11 or newer is required.")
PY
NODE_VERSION="$(node -p "process.versions.node")"
NODE_MAJOR="${NODE_VERSION%%.*}"
[[ "$NODE_MAJOR" =~ ^[0-9]+$ ]] || { echo "ERROR: Unable to determine Node.js version: $NODE_VERSION" >&2; exit 1; }
(( NODE_MAJOR >= 24 )) || { echo "ERROR: Node.js 24 or newer is required; found $NODE_VERSION." >&2; exit 1; }
if ! NPM_VERSION="$(npm --version 2>&1)"; then
  printf 'ERROR: npm failed to execute under Node.js %s. Runtime installation is blocked.\n%s\n' "$NODE_VERSION" "$NPM_VERSION" >&2
  exit 1
fi
printf 'Runtime toolchain: Node.js %s, npm %s\n' "$NODE_VERSION" "$NPM_VERSION"
cd "$SCRIPT_DIR"
[[ -f requirements-runtime.txt ]] || { echo "ERROR: requirements-runtime.txt is missing." >&2; exit 1; }
[[ -f package.json && -f package-lock.json ]] || { echo "ERROR: root package.json and package-lock.json are required." >&2; exit 1; }
[[ -f server_9898.js && -f Unified_Server.js ]] || { echo "ERROR: canonical Node entrypoints are missing." >&2; exit 1; }
"$PYTHON_BIN" -m venv .venv
VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python"
PIP_ARGS=()
NPM_ARGS=()
if (( OFFLINE )); then PIP_ARGS+=(--no-index); NPM_ARGS+=(--offline)
else "$VENV_PYTHON" -m pip install --upgrade pip; fi
"$VENV_PYTHON" -m pip install "${PIP_ARGS[@]}" -r requirements-runtime.txt
npm ci "${NPM_ARGS[@]}" --ignore-scripts
npm ci --prefix node-bridge "${NPM_ARGS[@]}" --ignore-scripts
"$VENV_PYTHON" - <<'PY'
import websockets
print(f"Python runtime dependencies verified (websockets {websockets.__version__})")
PY
node --check server_9898.js
node --check Unified_Server.js
node --check server.js
node --check node-bridge/server.js
echo "Installation complete. Configure the approved local inference provider, then run ./START_SERVER.sh."
