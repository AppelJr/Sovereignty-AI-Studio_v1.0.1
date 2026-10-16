#!/usr/bin/env python3
"""
Harden DevAssist420_Test.html against CodeQL Critical alerts:
  - Code injection (#588/#589): new Function(bridge-supplied code)
  - SSRF (#530/#531): WebSocket/fetch to CFG.bridge*Url

Surgical string replacements only.

  python3 scripts/xai-grok/harden_codeql_agent_bridge.py DevAssist420_Test.html
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

LOOPBACK_HELPER = """
/* Gate One: loopback-only bridge URL guard (CodeQL SSRF #530/#531) */
function _sgIsLoopbackUrl(u){
  try{
    var s=String(u||'');
    var m=s.match(/^(wss?|https?):\\/\\/([^\\/:?]+)(?::(\\d+))?/i);
    if(!m)return false;
    var host=m[2].toLowerCase();
    if(host==='127.0.0.1'||host==='localhost'||host==='[::1]'||host==='::1')return true;
    return false;
  }catch(e){return false;}
}
function _sgAssertLoopback(u,kind){
  if(_sgIsLoopbackUrl(u))return true;
  try{log('error','BLOCKED non-loopback '+kind+': '+String(u).slice(0,80));}catch(e){}
  try{auditEntry('SSRF_BLOCKED',{kind:kind,url:String(u).slice(0,120)});}catch(e){}
  return false;
}
"""

NEW_APPLY = """function applyPatch(code,pid,fromBridge){
  var entry={id:pid,ts:Date.now(),code:String(code||'').slice(0,200),status:'pending',fromBridge:!!fromBridge};
  _patchLog.unshift(entry); if(_patchLog.length>100)_patchLog.pop();
  /* CodeQL #588/#589: never execute remote/bridge-supplied code strings */
  if(fromBridge || !window._sgOwnerAllowLivePatch){
    entry.status='denied';
    entry.error='LIVE_PATCH_DENIED';
    try{log('error','Patch denied (Gate One): '+pid+' fromBridge='+!!fromBridge);}catch(e){}
    try{auditEntry('PATCH_DENIED',{id:pid,fromBridge:!!fromBridge});}catch(e){}
    return false;
  }
  if(CFG.patchSandbox){ try{new Function(code);}catch(e){ entry.status='syntax_error'; entry.error=e.message; log('error','Patch syntax error: '+pid,e.message); auditEntry('PATCH_REJECTED',{id:pid,err:e.message}); return false; } }
  try{
    var fn=new Function('window','document','SGCrypto','BRIDGE','toast','addAudit',code);
    fn(window,document,window.SGCrypto,window.BRIDGE,window.toast,window.addAudit);
    entry.status='applied'; log('info','Patch applied: '+pid); auditEntry('PATCH_APPLIED',{id:pid,fromBridge:fromBridge}); return true;
  }catch(e){ entry.status='runtime_error'; entry.error=e.message; log('error','Patch runtime error: '+pid,e.message); auditEntry('PATCH_FAILED',{id:pid,err:e.message}); return false; }
}"""


def harden(text: str) -> tuple[str, list[str]]:
    changes: list[str] = []
    if "_sgIsLoopbackUrl" not in text:
        if "function bridgeConnect(){" in text:
            text = text.replace(
                "function bridgeConnect(){",
                LOOPBACK_HELPER + "\nfunction bridgeConnect(){",
                1,
            )
            changes.append("loopback_helper")
    old_ws = "_ws=new WebSocket(CFG.bridgeWsUrl);"
    new_ws = (
        "if(!_sgAssertLoopback(CFG.bridgeWsUrl,'WebSocket'))"
        "{ _wsState='error'; updateDot(); return; } "
        "_ws=new WebSocket(CFG.bridgeWsUrl);"
    )
    if old_ws in text:
        text = text.replace(old_ws, new_ws, 1)
        changes.append("websocket_guard")
    old_fetch = (
        "try{fetch(CFG.bridgeHttpUrl,{method:'POST',"
        "headers:{'Content-Type':'application/json'},body:s})"
        ".catch(function(){});}catch(e){}"
    )
    new_fetch = (
        "try{if(_sgAssertLoopback(CFG.bridgeHttpUrl,'fetch'))"
        "fetch(CFG.bridgeHttpUrl,{method:'POST',"
        "headers:{'Content-Type':'application/json'},body:s})"
        ".catch(function(){});}catch(e){}"
    )
    if old_fetch in text:
        text = text.replace(old_fetch, new_fetch, 1)
        changes.append("fetch_guard")
    old_cfg = (
        "if(msg.type==='agent_config'){ Object.assign(CFG,msg.config||{}); "
        "saveCFG(); log('info','Config from bridge',msg.config); }"
    )
    new_cfg = (
        "if(msg.type==='agent_config'){ var _c=msg.config||{}; "
        "var _allow=['autoRepair','logLevel','repairThrottleMs',"
        "'alertThreshold','sealIntervalMs','maxRepairLog','maxErrorLog']; "
        "for(var _i=0;_i<_allow.length;_i++){ "
        "if(_c[_allow[_i]]!==undefined) CFG[_allow[_i]]=_c[_allow[_i]]; } "
        "if(_c.bridgeWsUrl && _sgIsLoopbackUrl(_c.bridgeWsUrl)) "
        "CFG.bridgeWsUrl=_c.bridgeWsUrl; "
        "if(_c.bridgeHttpUrl && _sgIsLoopbackUrl(_c.bridgeHttpUrl)) "
        "CFG.bridgeHttpUrl=_c.bridgeHttpUrl; "
        "saveCFG(); log('info','Config from bridge (allowlisted)',"
        "{keys:Object.keys(_c)}); }"
    )
    if old_cfg in text:
        text = text.replace(old_cfg, new_cfg, 1)
        changes.append("config_allowlist")
    old_patch = (
        "if(msg.type==='agent_patch'&&msg.code&&CFG.patchSandbox){ "
        "applyPatch(msg.code,'bridge-'+Date.now(),true); }"
    )
    new_patch = (
        "if(msg.type==='agent_patch'&&msg.code){ "
        "applyPatch(msg.code,'bridge-'+Date.now(),true); }"
    )
    if old_patch in text:
        text = text.replace(old_patch, new_patch, 1)
        changes.append("agent_patch_handler")
    m = re.search(
        r"function applyPatch\(code,pid,fromBridge\)\{.*?\n\}",
        text,
        re.DOTALL,
    )
    if m:
        text = text[: m.start()] + NEW_APPLY + text[m.end() :]
        changes.append("applyPatch_gate")
    return text, changes


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "usage: harden_codeql_agent_bridge.py <html-path>",
            file=sys.stderr,
        )
        return 2
    path = Path(sys.argv[1])
    raw = path.read_text(encoding="utf-8", errors="replace")
    fixed, changes = harden(raw)
    if not changes:
        print("no target patterns found (already hardened?)")
        return 0
    path.write_text(fixed, encoding="utf-8")
    print("applied:", ", ".join(changes), "->", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
