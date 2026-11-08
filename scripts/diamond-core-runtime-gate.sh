#!/usr/bin/env bash
# Diamond Lattice 5D Core runtime gate.
# Fail closed without mutating the checked-out repository or accessing the network.
set -Eeuo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_BIN="${CARGO_BIN:-cargo}"
CORE_SOURCE="$ROOT_DIR/diamond-core"

[[ -f "$CORE_SOURCE/Cargo.toml" ]] || { echo "DIAMOND_CORE=DENY missing Cargo.toml" >&2; exit 1; }
command -v "$CARGO_BIN" >/dev/null 2>&1 || { echo "DIAMOND_CORE=DENY cargo unavailable" >&2; exit 1; }

# The repository does not carry a Cargo.lock for this standalone crate.
# Test a temporary copy so Cargo can resolve from the local cache without
# creating a lockfile or target artifacts inside the user's working tree.
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/diamond-core-gate.XXXXXX")"
cleanup() {
  rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT INT TERM
cp -R "$CORE_SOURCE" "$TMP_DIR/diamond-core"

CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$TMP_DIR/target" \
  "$CARGO_BIN" test --manifest-path "$TMP_DIR/diamond-core/Cargo.toml" --all-targets

echo "DIAMOND_CORE=PASS"
echo "DIAMOND_CORE_MANIFEST=$CORE_SOURCE/Cargo.toml"
echo "DIAMOND_CORE_MODE=offline-temporary-copy"
