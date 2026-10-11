import hashlib
"""sovereign_init.py — fail-closed secret initialization.

The previous default secret was the literal string "sovereign-default-secret",
which is not a secret. This module now refuses to run without a real one.
"""
import os
import sys

_ENV_KEY = "SOVEREIGN_API_KEY_SECRET"
_MIN_LEN = 32


def _secret() -> bytes:
    secret = os.environ.get(_ENV_KEY)
    if not secret:
        print(f"FAIL — no secret found. Set the environment variable "
              f"{ENV_KEY} to a value of at least {MIN_LEN} characters. "
              f"Refusing to run with a default.", file=sys.stderr)
        sys.exit(1)
    if len(secret) < MIN_LEN:
        print(f"FAIL — secret is {len(secret)} characters; minimum is "
              f"{MIN_LEN}. Refusing to run.", file=sys.stderr)
        sys.exit(1)
    return secret.encode()


def derive_api_key(service_name: str, length: int = 32) -> str:
    digest = hashlib.sha256(_secret() + b":" + service_name.encode()).hexdigest()
    while len(digest) < length * 2:
        digest += hashlib.sha256(digest.encode()).hexdigest()
    return digest[: length * 2]
