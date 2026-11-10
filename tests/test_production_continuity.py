from __future__ import annotations
import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("continuity_checkpoint",ROOT/"scripts/continuity_checkpoint.py")
assert SPEC and SPEC.loader
module=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=module;SPEC.loader.exec_module(module)
class ContinuityTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.roadmap=json.loads((ROOT/"roadmap/sovereignty-production-roadmap.json").read_text())
  self.rp=self.root/"roadmap.json";self.rp.write_text(json.dumps(self.roadmap));self.ledger=self.root/"private"/"checkpoints.jsonl"
 def tearDown(self): self.tmp.cleanup()
 def test_seed_digest(self): self.assertEqual(self.roadmap["checkpoints"][0]["digest"],module.checkpoint_digest(self.roadmap["checkpoints"][0]))

 def test_unpersisted_seed_is_not_a_pass(self):
  report=module.verify(self.ledger,self.rp)
  self.assertEqual(report["status"],"UNPERSISTED_SEED")
  self.assertFalse(report["resume_allowed"])

 def test_append_link_and_verify(self):
  cp=module.create(self.ledger,self.rp,"CONTINUITY-002","Run tests",[],[])["checkpoint"]
  self.assertEqual(cp["sequence"],1);self.assertEqual(cp["previous_checkpoint_id"],"SOVEREIGNTY-CONTINUITY-001")
  self.assertEqual(module.verify(self.ledger,self.rp)["count"],2)

 def test_progress_and_blockers_carry_forward(self):
  seed=self.roadmap["checkpoints"][0]
  seed["completed"]=[]
  seed["pending"]=["task-a","task-b"]
  seed["blockers"]=[]
  seed["digest"]=module.checkpoint_digest(seed)
  self.rp.write_text(json.dumps(self.roadmap))
  first=module.create(self.ledger,self.rp,"CONTINUITY-002","Continue task-b",["task-a"],["MODEL_MISSING"],["task-c"],[])["checkpoint"]
  self.assertEqual(first["completed"],["task-a"])
  self.assertEqual(first["pending"],["task-b","task-c"])
  self.assertEqual(first["blockers"],["MODEL_MISSING"])
  self.assertEqual(first["status"],"BLOCKED")
  second=module.create(self.ledger,self.rp,"CONTINUITY-003","Verify next task",["task-b"],[],[],["MODEL_MISSING"])["checkpoint"]
  self.assertEqual(second["completed"],["task-a","task-b"])
  self.assertEqual(second["pending"],["task-c"])
  self.assertEqual(second["blockers"],[])
  self.assertEqual(second["status"],"ACTIVE")
  report=module.verify(self.ledger,self.rp)
  self.assertEqual(report["signature_status"],"UNSIGNED")
  self.assertFalse(report["resume_allowed"])


 def test_verify_cli_exits_nonzero_for_unpersisted_seed(self):
  original=sys.argv
  try:
   sys.argv=["continuity_checkpoint.py","verify","--roadmap",str(self.rp),"--ledger",str(self.ledger)]
   self.assertEqual(module.main(),1)
  finally: sys.argv=original

 def test_create_cli_succeeds_without_authorizing_resume(self):
  original=sys.argv
  try:
   sys.argv=["continuity_checkpoint.py","create","--id","CONTINUITY-002","--roadmap",str(self.rp),"--ledger",str(self.ledger)]
   self.assertEqual(module.main(),0)
  finally: sys.argv=original
  self.assertFalse(module.verify(self.ledger,self.rp)["resume_allowed"])


 def test_signature_status_claim_never_authorizes_resume(self):
  module.create(self.ledger,self.rp,"CONTINUITY-002","Resume only after verification",[],[])
  rows=self.ledger.read_text().splitlines()
  item=json.loads(rows[-1])
  item["checkpoint"]["signature_status"]="SIGNED_VERIFIED"
  item["checkpoint"]["digest"]=module.checkpoint_digest(item["checkpoint"])
  item["digest"]=item["checkpoint"]["digest"]
  rows[-1]=module.canonical_bytes(item).decode("utf-8")
  self.ledger.write_text("\n".join(rows)+"\n")
  report=module.verify(self.ledger,self.rp)
  self.assertEqual(report["signature_status"],"SIGNED_VERIFIED")
  self.assertEqual(report["signature_verification"],"NOT_RUN")
  self.assertFalse(report["resume_allowed"])

 def test_tamper_rejected(self):
  module.create(self.ledger,self.rp,"CONTINUITY-002","Run tests",[],[]);rows=self.ledger.read_text().splitlines();item=json.loads(rows[-1]);item["checkpoint"]["next_action"]="tampered";rows[-1]=json.dumps(item);self.ledger.write_text("\n".join(rows)+"\n")
  with self.assertRaisesRegex(module.ContinuityError,"digest mismatch"): module.verify(self.ledger,self.rp)
 def test_duplicate_id_rejected(self):
  module.create(self.ledger,self.rp,"CONTINUITY-002","Run tests",[],[])
  with self.assertRaisesRegex(module.ContinuityError,"already exists"): module.create(self.ledger,self.rp,"CONTINUITY-002","again",[],[])
 def test_symlink_rejected(self):
  self.ledger.parent.mkdir(parents=True);target=self.root/"target";target.write_text("");self.ledger.symlink_to(target)
  with self.assertRaisesRegex(module.ContinuityError,"symlink"): module.create(self.ledger,self.rp,"CONTINUITY-002","Run tests",[],[])
 def test_bad_id_rejected(self):
  with self.assertRaisesRegex(module.ContinuityError,"invalid checkpoint ID"): module.create(self.ledger,self.rp,"../escape","Run tests",[],[])
 def test_schema_and_seed_validate(self):
  schema=json.loads((ROOT/"schemas/sovereignty-production-continuity.schema.json").read_text())
  self.assertEqual(list(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(self.roadmap)),[])
 def test_production_requires_gates_and_owner_ref(self):
  schema=json.loads((ROOT/"schemas/sovereignty-production-continuity.schema.json").read_text());candidate=json.loads(json.dumps(self.roadmap));candidate["release"]["status"]="PRODUCTION"
  self.assertTrue(list(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(candidate)))
  candidate["release"]["promotion_authorized"]=True;candidate["release"]["owner_acceptance_ref"]=None
  self.assertTrue(list(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(candidate)))
  candidate["release"].pop("owner_acceptance_ref",None)
  self.assertTrue(list(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(candidate)))

 def test_unsafe_state_root_rejected(self):
  original=module.STATE_ROOT
  try:
   module.STATE_ROOT=Path("/")
   with self.assertRaisesRegex(module.ContinuityError,"unsafe SOVEREIGN_STATE_ROOT"):
    module.create(self.ledger,self.rp,"CONTINUITY-002","Run tests",[],[])
  finally:
   module.STATE_ROOT=original

if __name__=="__main__": unittest.main()
