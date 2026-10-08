#!/usr/bin/env bash
# =============================================================================
# init-sovereignty-family-tree.sh
# Device-local Sovereignty family-tree initializer.
#
# Modes (canonical runtime contract):
#   LOCAL   — default. Offline / loopback-only. No external hosts.
#   HYBRID  — loopback + explicitly authorized hosts (owner opt-in).
#   ONLINE  — remote traffic only when owner explicitly enables it.
#
# Network availability is not authorization.
# Silent promotion from LOCAL → HYBRID/ONLINE is forbidden.
# =============================================================================
set -euo pipefail

MODE_RAW="${1:-LOCAL}"
MODE="$(printf '%s' "$MODE_RAW" | tr '[:lower:]' '[:upper:]')"

case "$MODE" in
  LOCAL|HYBRID|ONLINE) ;;
  *)
    echo "ERROR: mode must be LOCAL | HYBRID | ONLINE (got: $MODE_RAW)" >&2
    echo "Usage: $0 [LOCAL|HYBRID|ONLINE]" >&2
    exit 2
    ;;
esac

ROOT="${SOVEREIGN_STATE_ROOT:-$HOME/Admin/On Device Memory Storage}"
TIMESTAMP_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STAMP_FILE="$(date -u +%Y%m%dT%H%M%SZ)"

# --- Mode policy (fail-closed defaults) --------------------------------------
NETWORK_ENABLED=false
EXTERNAL_MEMORY=false
ALLOWED_HOSTS='[]'
CLOUD_LAST_RESORT=false
REQUIRES_EXPLICIT_OWNER=false

case "$MODE" in
  LOCAL)
    NETWORK_ENABLED=false
    EXTERNAL_MEMORY=false
    ALLOWED_HOSTS='[]'
    CLOUD_LAST_RESORT=false
    REQUIRES_EXPLICIT_OWNER=false
    ;;
  HYBRID)
    # Owner must supply SOVEREIGN_ALLOWED_HOSTS (comma-separated) or we refuse.
    if [[ -z "${SOVEREIGN_ALLOWED_HOSTS:-}" ]]; then
      echo "ERROR: HYBRID requires SOVEREIGN_ALLOWED_HOSTS (comma-separated host list)." >&2
      echo "Example: SOVEREIGN_ALLOWED_HOSTS=127.0.0.1,localhost $0 HYBRID" >&2
      exit 3
    fi
    NETWORK_ENABLED=true
    EXTERNAL_MEMORY=false
    # Build JSON array from comma list
    ALLOWED_HOSTS="["
    first=1
    IFS=',' read -ra _hosts <<< "$SOVEREIGN_ALLOWED_HOSTS"
    for h in "${_hosts[@]}"; do
      h="$(printf '%s' "$h" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      [[ -z "$h" ]] && continue
      if [[ $first -eq 1 ]]; then first=0; else ALLOWED_HOSTS+=","; fi
      ALLOWED_HOSTS+="$(printf '"%s"' "$h")"
    done
    ALLOWED_HOSTS+="]"
    if [[ "$ALLOWED_HOSTS" == "[]" ]]; then
      echo "ERROR: HYBRID allowed-host list is empty after parse." >&2
      exit 3
    fi
    CLOUD_LAST_RESORT=false
    REQUIRES_EXPLICIT_OWNER=true
    ;;
  ONLINE)
    # ONLINE requires explicit owner affirmation env flag.
    if [[ "${SOVEREIGN_OWNER_ONLINE_ACK:-}" != "I_AUTHORIZE_ONLINE" ]]; then
      echo "ERROR: ONLINE requires SOVEREIGN_OWNER_ONLINE_ACK=I_AUTHORIZE_ONLINE" >&2
      echo "Network availability is not authorization." >&2
      exit 4
    fi
    NETWORK_ENABLED=true
    EXTERNAL_MEMORY="${SOVEREIGN_EXTERNAL_MEMORY:-false}"
    ALLOWED_HOSTS='["*"]'
    CLOUD_LAST_RESORT=true
    REQUIRES_EXPLICIT_OWNER=true
    ;;
esac

echo "Sovereignty family-tree init"
echo "  mode:     $MODE"
echo "  root:     $ROOT"
echo "  network:  $NETWORK_ENABLED"
echo "  external: $EXTERNAL_MEMORY"
echo "  hosts:    $ALLOWED_HOSTS"

# --- Directory tree ----------------------------------------------------------
mkdir -p "$ROOT/GitHub Copilot Local Storage"
mkdir -p "$ROOT/Anthropic Claude Fable Local Storage"
mkdir -p "$ROOT/OpenAI ChatGPT Codex Local Storage"
mkdir -p "$ROOT/X.AI Grok Local Storage"
mkdir -p "$ROOT/DuckAI Local Storage"
mkdir -p "$ROOT/DevAssist420 Local Hybrid Collaboration"
mkdir -p "$ROOT/Sovereignty AI"
mkdir -p "$ROOT/Router/Council/Claude"
mkdir -p "$ROOT/Router/Council/Ara-Grok"
mkdir -p "$ROOT/Router/Council/ChatGPT-Codex"
mkdir -p "$ROOT/Router/Council/DevAssist420"
mkdir -p "$ROOT/Router/Council/DuckAI"
mkdir -p "$ROOT/Router/Council/GitHub Copilot"
mkdir -p "$ROOT/Router/Council/Sovereignty AI"
mkdir -p "$ROOT/audit"
mkdir -p "$ROOT/hybrid"
mkdir -p "$ROOT/modes"

# --- Mode contract (canonical) ----------------------------------------------
cat > "$ROOT/modes/runtime-mode.json" <<EOF
{
  "version": "1.0.0",
  "mode": "$MODE",
  "timestamp": "$TIMESTAMP_UTC",
  "network_enabled": $NETWORK_ENABLED,
  "external_memory": $EXTERNAL_MEMORY,
  "allowed_hosts": $ALLOWED_HOSTS,
  "cloud_last_resort": $CLOUD_LAST_RESORT,
  "requires_explicit_owner": $REQUIRES_EXPLICIT_OWNER,
  "invariants": [
    "LOCAL is default",
    "HYBRID requires SOVEREIGN_ALLOWED_HOSTS",
    "ONLINE requires SOVEREIGN_OWNER_ONLINE_ACK=I_AUTHORIZE_ONLINE",
    "network availability is not authorization",
    "silent mode promotion is forbidden"
  ]
}
EOF

# --- Provider registry -------------------------------------------------------
REG="$ROOT/provider-registry.json"
if [[ -f "$REG" ]]; then
  cp -a "$REG" "$REG.bak.$STAMP_FILE"
fi

cat > "$REG" <<JSON
{
  "version": "1.0.0",
  "owner": "device-owner",
  "storage_root": "device-local",
  "runtime_mode": "$MODE",
  "network": $NETWORK_ENABLED,
  "external_memory": $EXTERNAL_MEMORY,
  "allowed_hosts": $ALLOWED_HOSTS,
  "cloud_last_resort": $CLOUD_LAST_RESORT,
  "providers": [
    {"id":"local.github_copilot","name":"GitHub Copilot","role":"implementation_review","storage":"GitHub Copilot Local Storage","network":false},
    {"id":"local.claude","name":"Anthropic Claude Fable","role":"long_context_analysis","storage":"Anthropic Claude Fable Local Storage","network":false},
    {"id":"local.openai_codex","name":"OpenAI ChatGPT Codex","role":"reasoning_and_coding","storage":"OpenAI ChatGPT Codex Local Storage","network":false},
    {"id":"local.grok","name":"X.AI Grok / Ara","role":"adversarial_review","storage":"X.AI Grok Local Storage","network":false},
    {"id":"local.duckai","name":"DuckAI","role":"privacy_research","storage":"DuckAI Local Storage","network":false},
    {"id":"local.devassist420","name":"DevAssist420","role":"hybrid_coordination","storage":"DevAssist420 Local Hybrid Collaboration","network":false},
    {"id":"local.sovereignty_ai","name":"Sovereignty AI","role":"owner_visible_router_and_council","storage":"Sovereignty AI","network":false}
  ],
  "wake_word": {
    "primary": "hey ara",
    "alternatives": ["on sovereignty ai", "devassist420"],
    "recognition": "local_engine_required",
    "remote_recognition": false,
    "status": "not_configured"
  }
}
JSON

# --- Audit README ------------------------------------------------------------
cat > "$ROOT/audit/README.txt" <<'EOF'
All provider actions must record:
who, what, when, where, why, how,
authorization, memory_loaded, network_accessed,
files_changed, and result.

Runtime modes:
  LOCAL  — offline / loopback-only (default)
  HYBRID — loopback + explicit allowed hosts
  ONLINE — owner-authorized remote (last resort)

Network is disabled by default. Remote listening is disabled.
Silent promotion between modes is forbidden.
EOF

# --- Permissions -------------------------------------------------------------
chmod 700 "$ROOT" 2>/dev/null || true
find "$ROOT" -type d -exec chmod 700 {} + 2>/dev/null || true
find "$ROOT" -type f -exec chmod 600 {} + 2>/dev/null || true

# --- Init receipt (evidence) -------------------------------------------------
REG_HASH="unknown"
if command -v sha256sum >/dev/null 2>&1; then
  REG_HASH="$(sha256sum "$REG" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  REG_HASH="$(shasum -a 256 "$REG" | awk '{print $1}')"
fi

RECEIPT="$ROOT/audit/init-$STAMP_FILE.json"
cat > "$RECEIPT" <<EOF
{
  "event": "sovereignty_family_tree_init",
  "timestamp": "$TIMESTAMP_UTC",
  "mode": "$MODE",
  "root": "$ROOT",
  "network_enabled": $NETWORK_ENABLED,
  "external_memory": $EXTERNAL_MEMORY,
  "allowed_hosts": $ALLOWED_HOSTS,
  "cloud_last_resort": $CLOUD_LAST_RESORT,
  "requires_explicit_owner": $REQUIRES_EXPLICIT_OWNER,
  "registry_sha256": "$REG_HASH"
}
EOF
chmod 600 "$RECEIPT" 2>/dev/null || true

echo "Initialization complete."
echo "  registry: $REG"
echo "  mode:     $ROOT/modes/runtime-mode.json"
echo "  receipt:  $RECEIPT"
