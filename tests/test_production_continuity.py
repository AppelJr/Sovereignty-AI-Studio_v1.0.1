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
 def test_append_link_and_verify(self):
  cp=module.create(self.ledger,self.rp,"CONTINUITY-002","Run tests",[],[])["checkpoint"]
  self.assertEqual(cp["sequence"],1);self.assertEqual(cp["previous_checkpoint_id"],"SOVEREIGNTY-CONTINUITY-001")
  self.assertEqual(module.verify(self.ledger,self.rp)["count"],2)
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
  candidate["release"]["promotion_authorized"]=True;candidate["release"].pop("owner_acceptance_ref",None)
  self.assertTrue(list(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(candidate)))
if __name__=="__main__": unittest.main()
