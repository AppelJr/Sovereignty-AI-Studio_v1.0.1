#!/usr/bin/env bash
# Fail closed if non-cryptographic RNG is introduced into policy/evidence paths.
set -euo pipefail

DIRS=(backend/policy backend/evidence)
existing=()
for dir in "${DIRS[@]}"; do
  [[ -d "$dir" ]] && existing+=("$dir")
done

if ((${#existing[@]})); then
  if grep -rnE 'Math\.random|^[[:space:]]*(import random|from random import)' "${existing[@]}" 2>/dev/null; then
    echo 'FAIL: randomness found in a policy/evidence path.' >&2
    exit 1
  fi
fi

echo 'OK: no non-cryptographic RNG in policy/evidence paths.'
