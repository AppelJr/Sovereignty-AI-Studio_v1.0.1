import json
from pathlib import Path
import pytest
from backend.sovereign_resilience import Candidate, FailoverDenied, MerkleTree, SovereignFailover, build_merkle_from_scarlog, sign_merkle_root_pqc, verify_proof

def test_merkle_proofs_odd_even_and_tamper():
    for n in (1,2,3,5,8):
        tree=MerkleTree([f"record-{i}" for i in range(n)])
        for i in range(n): assert verify_proof(tree.generate_proof(i))
        if n > 1:
            p=tree.generate_proof(0)
            assert not verify_proof(type(p)(p.leaf_hash,p.index,p.siblings,"0"*128,p.algorithm))

def test_invalid_index_and_pqc_placeholder_fail_closed():
    tree=MerkleTree(["entry"])
    with pytest.raises(ValueError): tree.generate_proof(True)
    with pytest.raises(RuntimeError, match="Real PQC signer"): sign_merkle_root_pqc(tree.get_root())

def test_malformed_scar_line_is_not_skipped(tmp_path: Path):
    path=tmp_path/"scar.jsonl"; path.write_text(json.dumps({"hash":"abc"})+"\n{bad}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="line 2"): build_merkle_from_scarlog(path)

def test_failover_uses_only_healthy_admitted_backup_and_audits():
    events=[]; invoked=[]
    router=SovereignFailover([Candidate("primary",lambda:False,lambda:True,lambda r:invoked.append("primary")),Candidate("backup",lambda:True,lambda:True,lambda r:invoked.append("backup") or "ok")],lambda e:events.append(e) or {"ok":True})
    result=router.execute({"prompt":"x"},request_id="r1",authorization_id="a1")
    assert result["service_id"]=="backup" and result["failed_over"] and invoked==["backup"]
    assert events[0]["result"]=="UNHEALTHY" and events[-1]["result"]=="SUCCESS"

def test_denied_backup_and_audit_failure_block_execution():
    invoked=[]
    router=SovereignFailover([Candidate("backup",lambda:True,lambda:False,lambda r:invoked.append(r))],lambda e:{"ok":True})
    with pytest.raises(FailoverDenied): router.execute({},request_id="r2",authorization_id="a2")
    assert not invoked
    router=SovereignFailover([Candidate("primary",lambda:True,lambda:True,lambda r:invoked.append(r))],lambda e:{"ok":False})
    with pytest.raises(FailoverDenied,match="SCAR persistence"): router.execute({},request_id="r3",authorization_id="a3")
    assert not invoked
