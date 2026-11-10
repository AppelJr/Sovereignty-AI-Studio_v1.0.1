"""Fail-closed MCP authorization and signed SCAR admission."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol
from sovereign.scar.ledger import EventClass, SCARActor, SCARLedger

@dataclass(frozen=True, slots=True)
class IdentityContext:
    identity_id: str
    authenticated: bool
    attestation: Mapping[str, Any]
    issuer_id: str = ""
    expires_at: str = ""

@dataclass(frozen=True, slots=True)
class CapabilityRecord:
    capability_id: str
    active: bool
    identity_id: str
    issuer_id: str
    expires_at: str
    grant_id: str

@dataclass(frozen=True, slots=True)
class OperationRequest:
    request_id: str
    identity: IdentityContext
    capability: CapabilityRecord
    operation: str
    mode: str
    workspace: str
    @property
    def identity_id(self) -> str: return self.identity.identity_id
    @property
    def capability_id(self) -> str: return self.capability.capability_id

@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    request_id: str
    identity_id: str
    capability_id: str
    operation: str
    mode: str
    policy_version: str
    decision: str
    reason: str
    timestamp: str

class AuditSink(Protocol):
    def record(self, decision: AuthorizationDecision) -> None: ...
    def record_execution(self, *, request: OperationRequest, result: str) -> None: ...

class SCARAuditSink:
    """Translate MCP decisions into the canonical signed SCAR ledger."""
    def __init__(self, ledger: SCARLedger) -> None: self.ledger = ledger
    def record(self, decision: AuthorizationDecision) -> None:
        self.ledger.append_event("MCP_AUTHORIZATION_DECISION", actor=SCARActor.DEVICE,
            event_class=EventClass.SECURITY, capability_id=decision.capability_id or None,
            timestamp=decision.timestamp, metadata={"request_id":decision.request_id,
            "identity_id":decision.identity_id,"operation":decision.operation,"mode":decision.mode,
            "policy_version":decision.policy_version,"decision":decision.decision,"reason":decision.reason})
    def record_execution(self, *, request: OperationRequest, result: str) -> None:
        self.ledger.append_event("MCP_EXECUTION_RESULT", actor=SCARActor.DEVICE,
            event_class=EventClass.AUDIT, capability_id=request.capability_id,
            metadata={"request_id":request.request_id,"identity_id":request.identity_id,
            "operation":request.operation,"mode":request.mode,"result":result})

class UnavailableAuditSink:
    def record(self, decision: AuthorizationDecision) -> None:
        raise RuntimeError("trusted SCAR audit sink is not configured")
    def record_execution(self, *, request: OperationRequest, result: str) -> None:
        raise RuntimeError("trusted SCAR audit sink is not configured")

class MCPAuthorityAdapter:
    def __init__(self, policy: Mapping[str, Any], audit: AuditSink | None = None) -> None:
        self.policy=policy
        self.audit=audit or UnavailableAuditSink()
    @staticmethod
    def _future(value: str, now: datetime) -> bool:
        try:
            parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
            return parsed.tzinfo is not None and parsed > now
        except (TypeError,ValueError,AttributeError): return False
    def _valid_attestation(self, attestation: Mapping[str,Any]) -> bool:
        required=self.policy.get("bridge_requirements",{})
        return isinstance(required,Mapping) and bool(attestation) and all(attestation.get(k)==v for k,v in required.items())
    def authorize(self, request: OperationRequest) -> AuthorizationDecision:
        now=datetime.now(timezone.utc); timestamp=now.isoformat()
        version=str(self.policy.get("version","unknown")); grant=request.capability
        capabilities=self.policy.get("capabilities",{})
        capability=capabilities.get(request.capability_id) if isinstance(capabilities,Mapping) else None
        reason="capability permitted"
        if not request.request_id.strip(): reason="missing request id"
        elif not request.identity.authenticated or not request.identity.identity_id.strip(): reason="unauthenticated identity"
        elif not request.identity.issuer_id.strip() or not self._future(request.identity.expires_at,now): reason="untrusted or expired identity session"
        elif not grant.active: reason="missing or inactive authority-issued capability"
        elif grant.identity_id != request.identity.identity_id: reason="capability subject mismatch"
        elif not grant.issuer_id.strip() or not grant.grant_id.strip() or not self._future(grant.expires_at,now): reason="invalid or expired capability grant"
        elif not isinstance(capability,Mapping): reason="unknown capability"
        elif request.mode not in set(capability.get("allowed_modes",())): reason="mode not permitted"
        elif bool(capability.get("mutation")): reason="mutation disabled by MCP policy"
        elif bool(capability.get("requires_approval")): reason="explicit owner approval required"
        elif capability.get("classification")=="authority": reason="MCP cannot grant authority"
        elif not self._valid_attestation(request.identity.attestation): reason="invalid local attestation"
        decision="ALLOW" if reason=="capability permitted" else "DENY"
        result=AuthorizationDecision(request.request_id,request.identity_id,request.capability_id,
            request.operation,request.mode,version,decision,reason,timestamp)
        try: self.audit.record(result)
        except Exception as error:
            return AuthorizationDecision(result.request_id,result.identity_id,result.capability_id,
                result.operation,result.mode,result.policy_version,"DENY",
                f"SCAR admission failure: {type(error).__name__}",result.timestamp)
        return result
