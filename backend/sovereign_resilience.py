"""Fail-closed service failover and SCAR Merkle proofs for Sovereignty AI Studio."""
from __future__ import annotations
import hashlib, json, time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

try:
    import blake3  # type: ignore[import-not-found]
except ImportError:
    blake3 = None

class FailoverDenied(RuntimeError):
    """No healthy, independently admitted service could safely complete a request."""

@dataclass(frozen=True, slots=True)
class Candidate:
    service_id: str
    healthy: Callable[[], bool]
    admitted: Callable[[], bool]
    invoke: Callable[[dict[str, Any]], Any]

@dataclass(frozen=True, slots=True)
class MerkleProof:
    leaf_hash: str
    index: int
    siblings: tuple[dict[str, str], ...]
    root: str
    algorithm: str = "SHA3-512"

def _digest(data: bytes, algorithm: str) -> str:
    sha = hashlib.sha3_512(data).digest()
    if algorithm == "SHA3-512":
        return sha.hex()
    if algorithm == "SHA3-512+BLAKE3":
        if blake3 is None:
            raise RuntimeError("BLAKE3 is unavailable; refusing dual-hash operation")
        return hashlib.sha3_512(sha + blake3.blake3(data).digest()).hexdigest()
    raise ValueError("Unsupported hash algorithm")

def _parent(left: str, right: str, algorithm: str) -> str:
    a, b = bytes.fromhex(left), bytes.fromhex(right)
    if len(a) != 64 or len(b) != 64:
        raise ValueError("Merkle nodes must be 512-bit hashes")
    return _digest(b"\x01" + a + b, algorithm)

class MerkleTree:
    def __init__(self, leaves: Iterable[str | bytes] | None = None, *, algorithm: str = "SHA3-512"):
        if algorithm not in ("SHA3-512", "SHA3-512+BLAKE3"):
            raise ValueError("Unsupported hash algorithm")
        self.algorithm = algorithm
        self.leaves = tuple(_digest(b"\x00" + (v.encode() if isinstance(v, str) else v), algorithm) for v in (leaves or ()))
        self.levels: list[list[str]] = []
        self.root: str | None = None
        if self.leaves:
            level = list(self.leaves); self.levels.append(level)
            while len(level) > 1:
                nxt = [_parent(level[i], level[i + 1] if i + 1 < len(level) else level[i], algorithm) for i in range(0, len(level), 2)]
                self.levels.append(nxt); level = nxt
            self.root = level[0]

    def get_root(self) -> str | None:
        return self.root

    def generate_proof(self, index: int) -> MerkleProof:
        if isinstance(index, bool) or not isinstance(index, int) or index < 0 or index >= len(self.leaves):
            raise ValueError("Merkle leaf index out of range")
        idx = index; siblings: list[dict[str, str]] = []
        for level in self.levels[:-1]:
            sibling = idx ^ 1
            siblings.append({"hash": level[sibling] if sibling < len(level) else level[idx], "position": "left" if idx % 2 else "right"})
            idx //= 2
        assert self.root is not None
        return MerkleProof(self.leaves[index], index, tuple(siblings), self.root, self.algorithm)

def verify_proof(proof: MerkleProof) -> bool:
    try:
        if not isinstance(proof, MerkleProof) or not proof.root or len(proof.root) != 128:
            return False
        current = proof.leaf_hash
        for item in proof.siblings:
            if not isinstance(item, dict) or set(item) != {"hash", "position"}:
                return False
            if item["position"] == "left": current = _parent(item["hash"], current, proof.algorithm)
            elif item["position"] == "right": current = _parent(current, item["hash"], proof.algorithm)
            else: return False
        return current == proof.root
    except (TypeError, ValueError, RuntimeError, KeyError):
        return False

def build_merkle_from_scarlog(path: Path, *, algorithm: str = "SHA3-512") -> MerkleTree:
    """Reject malformed records rather than silently omitting audit evidence."""
    leaves = []
    if not path.exists(): return MerkleTree([], algorithm=algorithm)
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip(): continue
            try: entry = json.loads(line)
            except json.JSONDecodeError as exc: raise ValueError(f"Malformed SCAR JSONL at line {number}") from exc
            if not isinstance(entry, dict) or not isinstance(entry.get("hash"), str) or not entry["hash"]:
                raise ValueError(f"SCAR entry at line {number} has no hash")
            leaves.append(entry["hash"])
    return MerkleTree(leaves, algorithm=algorithm)

def sign_merkle_root_pqc(root: str, *, signer: Callable[[bytes], bytes] | None = None, public_key: bytes | None = None, node_id: str = "gateone-merkle") -> dict[str, Any]:
    """Use a real injected ML-DSA signer; never return fabricated signatures or keys."""
    if not isinstance(root, str) or len(root) != 128:
        raise ValueError("root must be a 512-bit hex digest")
    bytes.fromhex(root)
    if signer is None or not callable(signer) or not public_key:
        raise RuntimeError("Real PQC signer and public key required; placeholder attestation refused")
    payload = {"node_id": node_id, "merkle_root": root, "timestamp": int(time.time()), "purpose": "scar_merkle_root_attestation", "algorithm": "ML-DSA-87"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = signer(canonical)
    if not isinstance(signature, bytes) or not signature: raise RuntimeError("PQC signer returned no signature")
    return {"algorithm": "ML-DSA-87", "payload": payload, "signature": signature.hex(), "public_key": public_key.hex(), "timestamp": payload["timestamp"]}

class SovereignFailover:
    """Ordered failover; every candidate must pass health and independent admission."""
    def __init__(self, candidates: Iterable[Candidate], audit: Callable[[dict[str, Any]], Any]):
        self.candidates = tuple(candidates); self.audit = audit
        ids = [c.service_id for c in self.candidates]
        if not ids or any(not isinstance(i, str) or not i.strip() for i in ids) or len(ids) != len(set(ids)):
            raise ValueError("Unique named service candidates required")
        if not callable(audit): raise ValueError("Mandatory SCAR audit callback required")

    def _record(self, request_id: str, authorization_id: str, service: str, result: str, failed: list[str]) -> None:
        receipt = self.audit({"who":"sovereign-failover-controller", "what":"service_failover_attempt", "when":int(time.time()), "where":service, "why":"health and independent admission gate", "how":"ordered fail-closed candidate evaluation", "authorization":authorization_id, "memory_loaded":False, "network_accessed":False, "files_changed":[], "request_id":request_id, "failed_services":list(failed), "result":result})
        if receipt is False or (isinstance(receipt, dict) and receipt.get("ok") is False):
            raise FailoverDenied("SCAR persistence unconfirmed; execution halted")

    def execute(self, request: dict[str, Any], *, request_id: str, authorization_id: str) -> dict[str, Any]:
        if not isinstance(request, dict) or not request_id or not authorization_id:
            raise FailoverDenied("request, request_id, and authorization_id required")
        failed: list[str] = []
        for c in self.candidates:
            try:
                if c.healthy() is not True:
                    failed.append(c.service_id); self._record(request_id, authorization_id, c.service_id, "UNHEALTHY", failed); continue
                if c.admitted() is not True:
                    failed.append(c.service_id); self._record(request_id, authorization_id, c.service_id, "ADMISSION_DENIED", failed); continue
                self._record(request_id, authorization_id, c.service_id, "EXECUTION_AUTHORIZED", failed)
                value = c.invoke(request)
                self._record(request_id, authorization_id, c.service_id, "SUCCESS", failed)
                return {"ok":True, "service_id":c.service_id, "result":value, "failed_over":bool(failed), "failed_services":failed}
            except FailoverDenied: raise
            except Exception:
                failed.append(c.service_id); self._record(request_id, authorization_id, c.service_id, "EXECUTION_FAILED", failed)
        self._record(request_id, authorization_id, "none", "NO_ADMITTED_SERVICE", failed)
        raise FailoverDenied("No healthy, independently admitted service completed the request")
