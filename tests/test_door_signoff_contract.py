"""Executable tests for door sign-off contract and SCAR event shape."""
from __future__ import annotations

import hashlib
import hmac
import time
import unittest

from src.security.door_signoff_contract import (
    AuthorizationIdentity,
    AuthorizationRequest,
    ContractError,
    DeviceIdentity,
    DoorDecision,
    DoorSignOff,
    PersonIdentity,
    ScarEventType,
    fresh_nonce,
    fresh_request_id,
)


class HmacVerifier:
    """Deterministic test verifier — real HMAC-SHA256, not a fake-always-true stub."""

    def verify(self, *, public_key: str, message: bytes, signature: str, scheme: str) -> bool:
        if scheme != "HMAC-SHA256":
            return False
        expected = hmac.new(public_key.encode("utf-8"), message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


def _sign(public_key: str, message: bytes) -> str:
    return hmac.new(public_key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _identity(**kw) -> AuthorizationIdentity:
    now = time.time()
    person = PersonIdentity(
        person_id=kw.get("person_id", "alice"),
        person_public_key=kw.get("person_public_key", "person-key-alice"),
        biometric_verified=kw.get("biometric_verified", True),
    )
    device = DeviceIdentity(
        device_id=kw.get("device_id", "iphone-1"),
        device_public_key=kw.get("device_public_key", "device-key-1"),
        device_attestation=kw.get("device_attestation", "attestation-digest"),
        imei=kw.get("imei", "123456789012345"),
        hardware_backed=True,
        policy_epoch=kw.get("policy_epoch", 42),
    )
    request = AuthorizationRequest(
        request_id=kw.get("request_id", fresh_request_id()),
        scope=kw.get("scope", "execute.deployment"),
        policy_epoch=kw.get("policy_epoch", 42),
        expiry=kw.get("expiry", now + 60),
        nonce=kw.get("nonce", fresh_nonce()),
        operation=kw.get("operation", "deploy"),
    )
    return AuthorizationIdentity(person=person, device=device, request=request)


class DoorSignOffTests(unittest.TestCase):
    def setUp(self):
        self.door = DoorSignOff(verifier=HmacVerifier())

    def test_missing_fields_raise_contract_error(self):
        with self.assertRaises(ContractError):
            PersonIdentity(person_id="", person_public_key="k")
        with self.assertRaises(ContractError):
            DeviceIdentity(device_id="d", device_public_key="", device_attestation="a")

    def test_signature_required(self):
        ident = _identity()
        result = self.door.evaluate(ident, expected_policy_epoch=42)
        self.assertEqual(result.decision, DoorDecision.DENY)
        self.assertEqual(result.reason, "signature_required")

    def test_valid_signoff_allows(self):
        ident = _identity()
        sig = _sign(ident.person.person_public_key, ident.signing_message())
        result = self.door.evaluate(
            ident,
            signature=sig,
            signature_scheme="HMAC-SHA256",
            expected_policy_epoch=42,
            allowed_scopes=["execute.deployment"],
        )
        self.assertEqual(result.decision, DoorDecision.ALLOW)
        self.assertEqual(result.scar_event_type, ScarEventType.DOOR_SIGNOFF_VERIFIED)

    def test_replay_denied(self):
        ident = _identity(request_id="req-fixed-1")
        sig = _sign(ident.person.person_public_key, ident.signing_message())
        first = self.door.evaluate(
            ident,
            signature=sig,
            signature_scheme="HMAC-SHA256",
            expected_policy_epoch=42,
        )
        self.assertEqual(first.decision, DoorDecision.ALLOW)
        second = self.door.evaluate(
            ident,
            signature=sig,
            signature_scheme="HMAC-SHA256",
            expected_policy_epoch=42,
        )
        self.assertEqual(second.decision, DoorDecision.DENY)
        self.assertEqual(second.reason, "request_id_replay")

    def test_expired_denied(self):
        ident = _identity(expiry=time.time() - 10)
        sig = _sign(ident.person.person_public_key, ident.signing_message())
        result = self.door.evaluate(
            ident,
            signature=sig,
            signature_scheme="HMAC-SHA256",
            expected_policy_epoch=42,
        )
        self.assertEqual(result.decision, DoorDecision.DENY)
        self.assertEqual(result.scar_event_type, ScarEventType.DOOR_SIGNOFF_EXPIRED)

    def test_wrong_signature_denied(self):
        ident = _identity()
        result = self.door.evaluate(
            ident,
            signature="deadbeef",
            signature_scheme="HMAC-SHA256",
            expected_policy_epoch=42,
        )
        self.assertEqual(result.decision, DoorDecision.DENY)
        self.assertEqual(result.reason, "signature_verification_failed")

    def test_field_change_invalidates_signature(self):
        ident = _identity()
        sig = _sign(ident.person.person_public_key, ident.signing_message())
        # Same signature, different person_id → envelope different → verify fails
        other = _identity(
            person_id="bob",
            person_public_key=ident.person.person_public_key,
            request_id=ident.request.request_id,
            nonce=ident.request.nonce,
            expiry=ident.request.expiry,
        )
        result = self.door.evaluate(
            other,
            signature=sig,
            signature_scheme="HMAC-SHA256",
            expected_policy_epoch=42,
        )
        self.assertEqual(result.decision, DoorDecision.DENY)

    def test_discuss_is_not_allow(self):
        ident = _identity()
        result = self.door.discuss(ident)
        self.assertEqual(result.decision, DoorDecision.DISCUSS)
        self.assertNotEqual(result.decision, DoorDecision.ALLOW)

    def test_scar_event_shape(self):
        ident = _identity()
        sig = _sign(ident.person.person_public_key, ident.signing_message())
        result = self.door.evaluate(
            ident,
            signature=sig,
            signature_scheme="HMAC-SHA256",
            expected_policy_epoch=42,
        )
        event = result.scar_event(prev_hash="GENESIS", actor="test")
        self.assertEqual(event["event"], "DOOR_SIGNOFF_VERIFIED")
        self.assertEqual(event["decision"], "ALLOW")
        self.assertEqual(event["person_id"], "alice")
        self.assertEqual(event["device_id"], "iphone-1")
        self.assertTrue(event["hash"].startswith("sha512:"))
        self.assertTrue(event["envelope_hash"].startswith("sha256:"))
        # No raw keys in SCAR
        self.assertNotIn("person_public_key", event)
        self.assertNotIn("device_public_key", event)

    def test_same_device_different_person_not_same_authority(self):
        alice = _identity(person_id="alice", person_public_key="key-a", device_id="shared-phone")
        bob = _identity(person_id="bob", person_public_key="key-b", device_id="shared-phone")
        self.assertEqual(alice.device.device_id, bob.device.device_id)
        self.assertNotEqual(alice.person.person_id, bob.person.person_id)
        self.assertNotEqual(alice.envelope_hash(), bob.envelope_hash())


if __name__ == "__main__":
    unittest.main()
