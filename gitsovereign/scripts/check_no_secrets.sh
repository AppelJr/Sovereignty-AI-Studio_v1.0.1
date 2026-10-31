#!/usr/bin/env bash
# Fail closed on obvious hardcoded credentials in source/config files.
set -euo pipefail

PATTERN='api[_-]?key[[:space:]]*[:=][[:space:]]*["'"'"'][a-zA-Z0-9]|sk-[a-zA-Z0-9]{20,}|secret[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{8,}|password[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']+'

if grep -rniE "$PATTERN" \
  --include='*.js' --include='*.mjs' --include='*.cjs' \
  --include='*.py' --include='*.json' --include='*.yaml' --include='*.yml' \
  --exclude-dir=node_modules --exclude-dir=.git .; then
  echo 'FAIL: possible hardcoded secret found above.' >&2
  exit 1
fi

echo 'OK: no hardcoded secrets found.'
