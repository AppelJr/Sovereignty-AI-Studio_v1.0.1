# DevAssist420_Test.html — xAI/Grok branch findings

**Source commit:** `58379af99b54ad8331b704f2abe4bb109b3a7182`  
**File:** `DevAssist420_Test.html` (~32,135 lines, ~1.6 MB)  
**Branch:** `xAI/Grok`  
**Approach:** multi-turn cleanup — no full rewrite in one shot

## Runtime path (owner)

```sh
node server.js &
python python3_bridge.py &
# browser
http://127.0.0.1:9897
```

## Primary bug: broken JS comments in BRIDGE STATUS SINGLETON

Around the `setConnected` function the comment terminators were corrupted:

1. Opens as `/* Local mode: ...` but closed with a single `/` instead of `*/`
2. Next line started with `/ Update all status elements...` instead of `/*`

That breaks parsing of the bridge status block so UI state may never track a real 200 from `:9897`.

### Turn 2 status — FIXED (surgical)

| Item | Status |
|---|---|
| Broken comment 1 | Restored to `*/` |
| Broken comment 2 | Restored to `/* ... */` |
| Full HTML rewrite | Not done (by design) |
| 1.6MB HTML via Contents API | Use apply script on device (file too large for single Contents API push) |

**Apply on clone / iSH:**

```sh
python3 scripts/xai-grok/fix_setConnected_comments.py DevAssist420_Test.html
```

Script path on branch: `scripts/xai-grok/fix_setConnected_comments.py`

Verified fixed region:

```javascript
function setConnected(yes, msg) {
_connected = yes;
/* Local mode: neutral blue bar, never red "Bridge offline" */
if(_isLocalMode()){
  ...
  return;
}
if (bar) bar.style.background = yes ? 'var(--acid,#00ffc8)' : '#ff3d6e';
if (txt) txt.textContent = msg || (yes ? '⚡ Bridge LIVE — Port 9897' : '⚠ Bridge offline — start bridge.py');
/* Update all status elements in the DOM */
document.querySelectorAll('[id="bridgeStatus"],[id="ftBridge"]').forEach(function(el){
...
});
}
```

## Secondary: status truth

- `_connected` + `setConnected(yes, msg)` is the intended singleton
- Local/offline mode intentionally suppresses bridge pings (offline-first) — correct
- Hybrid/online mode must bind to live health on **9897** (and 9899 if node is up)
- Terminal 200 OK + UI "not connected" remains a status-truth failure when not in local mode

## Forbidden stack scan (this file)

| Pattern | Result |
|---|---|
| React / Next / Vite / Vercel as runtime deps | Not loaded as UI framework |
| Google / Firebase / Meta block lists | Present as **deny lists** (correct) |
| SCAR patterns for CDN/jsdelivr/googleapis | Present |

## Multi-turn plan

| Turn | Work |
|---|---|
| **1** | Branch `xAI/Grok` created; findings recorded |
| **2 (this)** | Surgical comment fix verified; apply script on branch |
| **3** | Wire connection-status probe for 9897 iSH path; coherence check |
| **4** | Align registry + Gate contracts; PR when stable |

## Gate One

USER > AUTHORITY LAYER > MODELS > TOOLS > DATA  
Fail closed. Local first. ACTIVE only with live HTTP 200 evidence.  
Studio is integration host — not authority owner.
