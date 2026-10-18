# CodeQL Critical — DevAssist420_Test.html agent bridge

**Branch:** `xAI/Grok-sync` (base: `Collaboration`)  
**File:** `DevAssist420_Test.html`  
**Alerts addressed (same pattern family):**

| Alert | Type | Lines (approx) |
|---|---|---|
| #589, #588 | Code injection | applyPatch `new Function` ~4317–4319 |
| #531, #530 | SSRF | `WebSocket(CFG.bridgeWsUrl)` ~4272, `fetch(CFG.bridgeHttpUrl)` ~4298 |
| #484/#483/#318… | Same injection | DevAssist420SGHv119.html / SGHv119 copies |
| #426/#425/#101… | Same SSRF | Same copies |

## Root cause

1. **Injection:** `applyPatch` executes arbitrary strings via `new Function(...)`. Bridge message `agent_patch` can supply `msg.code`.
2. **SSRF:** `CFG.bridgeWsUrl` / `CFG.bridgeHttpUrl` used directly in WebSocket/fetch. `agent_config` did `Object.assign(CFG, msg.config)` so a hostile bridge could redirect egress.

## Gate One fix (surgical script)

```sh
python3 scripts/xai-grok/harden_codeql_agent_bridge.py DevAssist420_Test.html
```

Applies:

- **Loopback-only** URL guard for WS + fetch (127.0.0.1 / localhost / ::1)
- **Deny** `applyPatch` when `fromBridge` or when `window._sgOwnerAllowLivePatch` is not set
- **Allowlist** `agent_config` keys (no blind Object.assign; URLs only if loopback)

Owner explicit live-patch (local only, never default):

```js
window._sgOwnerAllowLivePatch = true; // owner-only, offline debugging
```

## Same pattern in other HTML copies

Run the same script against:

- `DevAssist420SGHv119.html`
- `SGHv119.html`
- `Frontend dashboard /DevAssist420SGHv119.html`

External skeleton copies under `external/` should stay quarantine / not ship.

## Not fixed in this pass

- #391 `server_9898.js` uncontrolled command line
- #15/#14/#13 Python subprocess command line
- #334 cert validation disabled in sanitizer.js

Track those next on `xAI/Grok-sync` after Collaboration update.

## Policy

Always update from **Collaboration** first. Resolve conflicts before further work.
