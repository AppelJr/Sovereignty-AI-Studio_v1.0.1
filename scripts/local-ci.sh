#!/usr/bin/env bash
# Device-local CI runner. Dependencies are consumed from the existing environment.
set -Eeuo pipefail
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
export SG_NETWORK_MODE=local SG_LOCAL_ONLY=1 SG_EXTERNAL_FEEDS=disabled CLOUD_FIRST=false
export PIP_NO_INDEX=1 PIP_NO_INPUT=1 PIP_DISABLE_PIP_VERSION_CHECK=1
export npm_config_offline=true npm_config_audit=false npm_config_fund=false
export NO_PROXY="*" no_proxy="*"
"${PYTHON:-python3}" scripts/validate-local-oauth.py
"${PYTHON:-python3}" -m pytest -q tests/test_oauth_local_generator.py
"${PYTHON:-python3}" scripts/validate_production_continuity.py
"${PYTHON:-python3}" -m pytest -q tests/test_production_continuity.py
exec "${PYTHON:-python3}" scripts/run-local-ci.py --ci-name "${SG_CI_NAME:-ara-hardened-unit-ci-local}" "$@"
