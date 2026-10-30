# Appel420(root) | GPT-6 (OpenAI) | WHAT: added certification and quarantine conformance tests | WHEN: 2026-10-30 | WHERE: backend/certification/test_engine.py | WHY: prove fail-closed model admission
import base64
import hashlib
import hmac
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.certification.engine import (
    REQUIRED_CHECKS,
    CertificationEngine,
    CertificationLedger,
)


SECRET = b"test-only-certification-secret"


def sign(payload: bytes) -> bytes:
    return hmac.new(SECRET, payload, hashlib.sha256).digest()


class CertificationEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = CertificationLedger(Path(self.temp.name) / "certification.jsonl")
        self.now = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
        self.engine = CertificationEngine(
            self.ledger,
            attestation_verifier=lambda alg, key, payload, sig: (
                alg == "TEST-HMAC-SHA256" and hmac.compare_digest(sign(payload), sig)
            ),
            owner_approval_verifier=lambda approval, payload, sig: (
                approval == "owner-approval-1" and hmac.compare_digest(sign(payload), sig)
            ),
            allowed_algorithms=frozenset({"TEST-HMAC-SHA256"}),
        )

    def tearDown(self):
        self.temp.cleanup()

    def record(self, **overrides):
        record = {
            "subject_id": "provider.local-model",
            "device_id": "device-001",
            "artifact_sha256": "a" * 64,
            "policy_version": "gateone-cert-v1",
            "checks": {name: "PASS" for name in REQUIRED_CHECKS},
            "issued_at": (self.now - timedelta(minutes=1)).isoformat(),
            "expires_at": (self.now + timedelta(hours=23)).isoformat(),
            "nonce": "b" * 64,
            "algorithm": "TEST-HMAC-SHA256",
            "public_key": base64.b64encode(b"test-public-key").decode(),
            "signature": "",
            "owner_approval_id": "owner-approval-1",
            "owner_signature": "",
        }
        record.update(overrides)
        payload = self.engine_payload(record)
        if "signature" not in overrides:
            record["signature"] = base64.b64encode(sign(payload)).decode()
        if "owner_signature" not in overrides:
            record["owner_signature"] = base64.b64encode(sign(payload)).decode()
        return record

    @staticmethod
    def engine_payload(record):
        import json
        return json.dumps({
            "subject_id": record["subject_id"],
            "device_id": record["device_id"],
            "artifact_sha256": record["artifact_sha256"],
            "policy_version": record["policy_version"],
            "checks": record["checks"],
            "issued_at": datetime.fromisoformat(record["issued_at"]).astimezone(timezone.utc).isoformat(),
            "expires_at": datetime.fromisoformat(record["expires_at"]).astimezone(timezone.utc).isoformat(),
            "nonce": record["nonce"],
            "owner_approval_id": record["owner_approval_id"],
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    def test_all_verified_evidence_certifies_exact_device_and_artifact(self):
        result = self.engine.evaluate(self.record(), expected_device_id="device-001", now=self.now)
        self.assertEqual(result.status, "CERTIFIED")
        self.assertTrue(self.ledger.is_admitted("provider.local-model", "device-001", "a" * 64))

    def test_failed_required_check_quarantines(self):
        checks = {name: "PASS" for name in REQUIRED_CHECKS}
        checks["adversarial"] = "FAIL"
        result = self.engine.evaluate(self.record(checks=checks), expected_device_id="device-001", now=self.now)
        self.assertEqual(result.status, "QUARANTINED")
        self.assertFalse(self.ledger.is_admitted("provider.local-model", "device-001", "a" * 64))

    def test_missing_check_does_not_certify(self):
        checks = {name: "PASS" for name in REQUIRED_CHECKS}
        del checks["provenance"]
        result = self.engine.evaluate(self.record(checks=checks), expected_device_id="device-001", now=self.now)
        self.assertEqual(result.status, "NOT_CERTIFIED")

    def test_device_mismatch_quarantines(self):
        result = self.engine.evaluate(self.record(), expected_device_id="different-device", now=self.now)
        self.assertEqual(result.status, "QUARANTINED")

    def test_expired_evidence_is_not_certified(self):
        result = self.engine.evaluate(
            self.record(expires_at=(self.now - timedelta(seconds=1)).isoformat()),
            expected_device_id="device-001",
            now=self.now,
        )
        self.assertEqual(result.status, "NOT_CERTIFIED")

    def test_invalid_signature_quarantines(self):
        result = self.engine.evaluate(
            self.record(signature=base64.b64encode(b"bad").decode()),
            expected_device_id="device-001",
            now=self.now,
        )
        self.assertEqual(result.status, "QUARANTINED")

    def test_unconfigured_verifiers_never_certify(self):
        engine = CertificationEngine(self.ledger, attestation_verifier=None, owner_approval_verifier=None)
        result = engine.evaluate(self.record(), expected_device_id="device-001", now=self.now)
        self.assertEqual(result.status, "NOT_CERTIFIED")

    def test_ledger_detects_tampering(self):
        self.engine.evaluate(self.record(), expected_device_id="device-001", now=self.now)
        path = self.ledger.path
        path.write_text(path.read_text().replace("CERTIFIED", "QUARANTINED"), encoding="utf-8")
        with self.assertRaises(RuntimeError):
            self.ledger.verify_chain()


if __name__ == "__main__":
    unittest.main()
