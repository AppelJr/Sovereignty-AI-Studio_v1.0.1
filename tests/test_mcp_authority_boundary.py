from __future__ import annotations
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from backend.mcp.mcp_governance import CapabilityRecord, IdentityContext, SCARAuditSink
from mcp_server import SovereignMCPServer
from sovereign.scar.ledger import SCARLedger

ATTESTATION={"trust_boundary":"local-only","network":False,"credentials":False,"mutation":False,"shell":False}
class TestSigner:
    def sign(self,payload:bytes)->bytes:
        import hashlib
        return hashlib.sha3_512(payload).digest()

def future(minutes=30):
    return (datetime.now(timezone.utc)+timedelta(minutes=minutes)).isoformat()

def identity(**overrides):
    values={"identity_id":"owner-device","authenticated":True,"attestation":ATTESTATION,
            "issuer_id":"trusted-host","expires_at":future()}
    values.update(overrides)
    return IdentityContext(**values)

def grant(**overrides):
    values={"capability_id":"workspace_read","active":True,"identity_id":"owner-device",
            "issuer_id":"gateone","expires_at":future(),"grant_id":"grant-001"}
    values.update(overrides)
    return CapabilityRecord(**values)

def call(server,tool="workspace_read",request_id="mcp-test"):
    return server.handle({"jsonrpc":"2.0","id":request_id,"method":"tools/call",
        "params":{"name":tool,"arguments":{"path":"note.txt"}}})

def test_anonymous_missing_grant_expired_and_subject_mismatch_deny():
    with TemporaryDirectory() as directory:
        Path(directory,"note.txt").write_text("private test payload")
        cases=[
            (None,grant(),"unauthenticated"),
            (identity(),None,"missing or inactive"),
            (identity(),grant(identity_id="other-owner"),"subject mismatch"),
            (identity(),grant(expires_at=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()),"expired"),
            (identity(authenticated=False),grant(),"unauthenticated"),
            (identity(attestation={"network":True}),grant(),"attestation"),
        ]
        for idx,(who,cap,reason) in enumerate(cases):
            ledger=SCARLedger("device:test",TestSigner())
            server=SovereignMCPServer(workspace=Path(directory),identity_context=who,
                capability_grants={"workspace_read":cap} if cap else {},audit_sink=SCARAuditSink(ledger))
            response=call(server,request_id=f"deny-{idx}")
            assert response["result"]["isError"],response
            assert len(ledger.events)==1
            assert ledger.verify_chain()
            assert "private test payload" not in json.dumps([e.signing_document() for e in ledger.events])

def test_authorized_read_executes_only_after_signed_scar_admission():
    with TemporaryDirectory() as directory:
        Path(directory,"note.txt").write_text("approved read")
        ledger=SCARLedger("device:test",TestSigner())
        server=SovereignMCPServer(workspace=Path(directory),identity_context=identity(),
            capability_grants={"workspace_read":grant()},audit_sink=SCARAuditSink(ledger))
        response=call(server)
        assert not response["result"].get("isError",False),response
        assert "approved read" in response["result"]["content"][0]["text"]
        assert len(ledger.events)==2
        assert [e.event_type for e in ledger.events]==["MCP_AUTHORIZATION_DECISION","MCP_EXECUTION_RESULT"]
        assert ledger.verify_chain()

def test_scar_unavailable_fails_closed_before_workspace_execution():
    class BrokenSink:
        def record(self,decision): raise OSError("SCAR unavailable")
        def record_execution(self,*,request,result): raise OSError("SCAR unavailable")
    with TemporaryDirectory() as directory:
        Path(directory,"note.txt").write_text("must not leak")
        server=SovereignMCPServer(workspace=Path(directory),identity_context=identity(),
            capability_grants={"workspace_read":grant()},audit_sink=BrokenSink())
        response=call(server)
        assert response["result"]["isError"]
        assert "authorization_denied" in response["result"]["content"][0]["text"]
        assert "must not leak" not in json.dumps(response)

def test_grant_is_not_created_from_mcp_arguments():
    with TemporaryDirectory() as directory:
        Path(directory,"note.txt").write_text("must not leak")
        ledger=SCARLedger("device:test",TestSigner())
        server=SovereignMCPServer(workspace=Path(directory),identity_context=identity(),audit_sink=SCARAuditSink(ledger))
        response=call(server)
        assert response["result"]["isError"]
        assert len(ledger.events)==1
        assert ledger.verify_chain()
