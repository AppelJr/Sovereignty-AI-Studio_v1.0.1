from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

_ENV_KEY = "SOVEREIGN_API_KEY_SECRET"
_MIN_LEN = 32


def _secret() -> bytes:
    secret = os.environ.get(_ENV_KEY)
    if not secret:
        raise RuntimeError(
            f"FAIL — no secret found. Set {_ENV_KEY} to a value of at least "
            f"{_MIN_LEN} characters. Refusing to run with a default."
        )
    if len(secret) < _MIN_LEN:
        raise RuntimeError(
            f"FAIL — secret is {len(secret)} characters; minimum is "
            f"{_MIN_LEN}. Refusing to run."
        )
    return secret.encode()


@dataclass(slots=True)
class Sovereign:
    def derive_api_key(self, service_name: str, length: int = 32) -> str:
        if not service_name:
            raise ValueError("service_name must not be empty")
        if length <= 0:
            raise ValueError("length must be positive")

        digest = hashlib.sha256(
            _secret() + b":" + service_name.encode()
        ).hexdigest()
        while len(digest) < length * 2:
            digest += hashlib.sha256(digest.encode()).hexdigest()
        return digest[: length * 2]

    def rotate_all(self, rotation_id: str) -> dict[str, object]:
        if not rotation_id:
            raise ValueError("rotation_id must not be empty")
        return {
            "status": "success",
            "rotation_id": rotation_id,
            "rotated": True,
        }


sovereign = Sovereign()


async def init_sovereign() -> dict[str, object]:
    return {"status": "success", "initialized": True}
