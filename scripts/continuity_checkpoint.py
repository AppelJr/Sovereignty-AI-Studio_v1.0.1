#!/usr/bin/env python3
"""Fail-closed SHA3-512 continuity checkpoint ledger; integrity is not identity auth."""
from __future__ import annotations
import argparse,fcntl,hashlib,json,os,re,sys
from datetime import datetime,timezone
from pathlib import Path
from typing import Any
ROOT=Path(__file__).resolve().parents[1]
DEFAULT_ROADMAP=ROOT/"roadmap/sovereignty-production-roadmap.json"
STATE_ROOT=Path(os.environ.get("SOVEREIGN_STATE_ROOT") or (Path.home()/"Admin"/"On Device Memory Storage")).expanduser()
DEFAULT_LEDGER=Path(os.environ.get("SOVEREIGNTY_CONTINUITY_LEDGER") or str(STATE_ROOT/"Sovereignty AI"/"continuity"/"checkpoints.jsonl")).expanduser()
ID_RE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
class ContinuityError(RuntimeError): pass
def canonical_bytes(value:Any)->bytes:
 return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def checkpoint_digest(cp:dict[str,Any])->str:
 return "sha3-512:"+hashlib.sha3_512(canonical_bytes({k:v for k,v in cp.items() if k!="digest"})).hexdigest()
def safe_parent(path:Path)->None:
 if not STATE_ROOT.is_absolute() or STATE_ROOT in (Path("/"), Path.home()) or ".." in STATE_ROOT.parts:
  raise ContinuityError("unsafe SOVEREIGN_STATE_ROOT")
 if not path.is_absolute() or path == Path("/") or path.parent == path:
  raise ContinuityError("unsafe ledger path")
 for ancestor in (path.parent, *path.parent.parents):
  if ancestor.exists() and ancestor.is_symlink():
   raise ContinuityError("refusing symlink checkpoint directory")
 path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 if path.is_symlink(): raise ContinuityError("refusing symlink ledger")
 if not path.parent.is_dir(): raise ContinuityError("ledger parent must be a real directory")
def read_ledger(path:Path)->list[dict[str,Any]]:
 if not path.exists(): return []
 if path.is_symlink() or not path.is_file(): raise ContinuityError("ledger path is not a regular file")
 rows=[]
 with path.open(encoding="utf-8") as stream:
  for n,line in enumerate(stream,1):
   if not line.strip(): raise ContinuityError(f"blank ledger line at {n}")
   try: item=json.loads(line)
   except json.JSONDecodeError as exc: raise ContinuityError(f"malformed ledger line {n}") from exc
   cp=item.get("checkpoint") if isinstance(item,dict) else None
   if not isinstance(cp,dict) or item.get("digest")!=checkpoint_digest(cp) or cp.get("digest")!=item.get("digest"): raise ContinuityError(f"checkpoint digest mismatch at line {n}")
   if cp.get("digest_algorithm")!="sha3-512": raise ContinuityError(f"unsupported checkpoint digest algorithm at line {n}")
   if cp.get("signature_status") not in ("UNSIGNED","SIGNED_UNVERIFIED","SIGNED_VERIFIED"): raise ContinuityError(f"invalid checkpoint signature status at line {n}")
   if cp.get("sequence")!=len(rows): raise ContinuityError(f"checkpoint sequence discontinuity at line {n}")
   prev=rows[-1]["checkpoint"] if rows else None
   if cp.get("previous_checkpoint_id")!=(prev["id"] if prev else None) or cp.get("previous_digest")!=(prev["digest"] if prev else None): raise ContinuityError(f"checkpoint predecessor mismatch at line {n}")
   rows.append(item)
 return rows
def verify(path:Path,roadmap_path:Path=DEFAULT_ROADMAP)->dict[str,Any]:
 rows=read_ledger(path)
 if not rows and roadmap_path.is_file():
  seeds=json.loads(roadmap_path.read_text()).get("checkpoints",[])
  if seeds and seeds[0].get("digest")==checkpoint_digest(seeds[0]):
   cp=seeds[0];return {"status":"UNPERSISTED_SEED","count":1,"latest_checkpoint":cp["id"],"latest_digest":cp["digest"],"integrity_verified":True,"resume_allowed":False,"resume_blocker":"SIGNATURE_VERIFIER_NOT_CONFIGURED","signature_verification":"NOT_RUN","source":"roadmap_seed_not_yet_persisted_to_local_ledger"}
 latest=rows[-1]["checkpoint"] if rows else None
 return {"status":"PASS" if rows else "EMPTY","count":len(rows),"latest_checkpoint":latest["id"] if latest else None,
         "latest_digest":rows[-1]["digest"] if rows else None,"integrity_verified":bool(rows),
         "signature_status":latest.get("signature_status") if latest else "UNSIGNED",
         "signature_verification":"NOT_RUN","resume_allowed":False,
         "resume_blocker":"SIGNATURE_VERIFIER_NOT_CONFIGURED"}
def create(path:Path,roadmap_path:Path,cid:str,next_action:str,completed:list[str],blockers:list[str],pending_add:list[str]|None=None,resolve_blockers:list[str]|None=None)->dict[str,Any]:
 if not ID_RE.fullmatch(cid): raise ContinuityError("invalid checkpoint ID")
 if not next_action.strip(): raise ContinuityError("next_action must not be empty")
 if roadmap_path.is_symlink() or not roadmap_path.is_file(): raise ContinuityError("roadmap must be a regular file")
 roadmap=json.loads(roadmap_path.read_text())
 if roadmap.get("schema_version")!="1.1.0": raise ContinuityError("unsupported roadmap schema_version")
 safe_parent(path);lock_path=path.with_suffix(path.suffix+".lock")
 if lock_path.is_symlink(): raise ContinuityError("refusing symlink lock file")
 fd=os.open(lock_path,os.O_CREAT|os.O_RDWR|getattr(os,"O_NOFOLLOW",0),0o600)
 with os.fdopen(fd,"r+") as lock:
  fcntl.flock(lock.fileno(),fcntl.LOCK_EX);rows=read_ledger(path)
  if not rows:
   seeds=roadmap.get("checkpoints",[])
   if not seeds or seeds[0].get("digest")!=checkpoint_digest(seeds[0]): raise ContinuityError("roadmap seed checkpoint missing or digest-invalid")
   seed=seeds[0];fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|getattr(os,"O_NOFOLLOW",0),0o600)
   with os.fdopen(fd,"ab") as out: out.write(canonical_bytes({"checkpoint":seed,"digest":seed["digest"]})+b"\n");out.flush();os.fsync(out.fileno())
   rows=read_ledger(path)
  prev=rows[-1]["checkpoint"]
  if any(x["checkpoint"]["id"]==cid for x in rows): raise ContinuityError("checkpoint ID already exists")
  completed_new=list(dict.fromkeys(completed))
  completed_all=list(dict.fromkeys(list(prev.get("completed",[]))+completed_new))
  pending_previous=list(prev.get("pending",roadmap["continuity"]["pending_work"]))
  pending_all=list(dict.fromkeys([item for item in pending_previous if item not in completed_new]+list(pending_add or [])))
  resolved=set(resolve_blockers or [])
  blockers_all=list(dict.fromkeys([item for item in prev.get("blockers",[]) if item not in resolved]+list(blockers)))
  cp={"id":cid,"sequence":len(rows),"created_at":datetime.now(timezone.utc).isoformat(),"status":"BLOCKED" if blockers_all else "ACTIVE","completed":completed_all,"pending":pending_all,"blockers":blockers_all,"verified_evidence":[],"next_action":next_action,"digest_algorithm":"sha3-512","previous_checkpoint_id":prev["id"],"previous_digest":prev["digest"],"signature_status":"UNSIGNED"}
  cp["digest"]=checkpoint_digest(cp);entry={"checkpoint":cp,"digest":cp["digest"]}
  fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|getattr(os,"O_NOFOLLOW",0),0o600)
  with os.fdopen(fd,"ab") as out: out.write(canonical_bytes(entry)+b"\n");out.flush();os.fsync(out.fileno())
  dfd=os.open(path.parent,os.O_RDONLY)
  try: os.fsync(dfd)
  finally: os.close(dfd)
  return entry
def main()->int:
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("command",choices=["create","verify","status"]);p.add_argument("--id",default="")
 p.add_argument("--next-action",default="Verify the next unfinished work item against the canonical repository.")
 p.add_argument("--completed",action="append",default=[]);p.add_argument("--blocker",action="append",default=[]);p.add_argument("--add-pending",action="append",default=[]);p.add_argument("--resolve-blocker",action="append",default=[])
 p.add_argument("--roadmap",type=Path,default=DEFAULT_ROADMAP);p.add_argument("--ledger",type=Path,default=DEFAULT_LEDGER);a=p.parse_args()
 try:
  if a.command=="create":
   if not a.id: raise ContinuityError("create requires --id")
   result={"status":"CREATED","resume_allowed":False,**create(a.ledger,a.roadmap,a.id,a.next_action,a.completed,a.blocker,a.add_pending,a.resolve_blocker)}
  else: result=verify(a.ledger,a.roadmap)
  print(json.dumps(result,indent=2,sort_keys=True));return 0 if result.get("status") in ("PASS","CREATED") else 1
 except (ContinuityError,OSError,ValueError,json.JSONDecodeError) as exc: print(f"BLOCKED: {exc}",file=sys.stderr);return 2
if __name__=="__main__": raise SystemExit(main())
