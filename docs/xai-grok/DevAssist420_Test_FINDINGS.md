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

Around the `setConnected` function the comment terminators are corrupted:

1. Opens as `/* Local mode: ...` but closes with a single `/` instead of `*/`
2. Next line starts with `/ Update all status elements...` instead of `/*`

That can break parsing of the bridge status block so UI state never tracks a real 200 from `:9897`.

**Fix (next turn):** surgical comment repair only — restore valid `/* ... */` around those two lines. Do not rewrite the whole file.

## Secondary: status truth

- `_connected` + `setConnected(yes, msg)` is the intended singleton
- Local/offline mode intentionally suppresses bridge pings (offline-first) — correct
- Hybrid/online mode must bind to live health on **9897** (and 9899 if node is up)
- Terminal 200 OK + UI “not connected” remains a status-truth failure when not in local mode

Use `studio-coherence` probe when wiring:

- `frontend/runtime/connection-status.js`
- `frontend/runtime/transport-health-patch.js`

## Forbidden stack scan (this file)

| Pattern | Result |
|---|---|
| React / Next / Vite / Vercel as runtime deps | Not loaded as UI framework (2 incidental string hits only) |
| Google / Firebase / Meta block lists | Present as **deny lists** (correct for zero-tolerance) |
| SCAR patterns for CDN/jsdelivr/googleapis | Present |

Control path stays vanilla HTML/JS. Keep it that way.

## Multi-turn plan

| Turn | Work |
|---|---|
| **1 (this)** | Branch `xAI/Grok` created; findings recorded; no HTML rewrite |
| **2** | Surgical fix of broken `setConnected` comments; optional status element bind |
| **3** | Wire connection-status probe for 9897 iSH path; coherence check |
| **4** | Align registry + Gate contracts; PR when stable |

## Gate One

USER > AUTHORITY LAYER > MODELS > TOOLS > DATA  
Fail closed. Local first. ACTIVE only with live HTTP 200 evidence.  
Studio is integration host — not authority owner.
