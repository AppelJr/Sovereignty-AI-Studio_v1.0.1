# Apply CodeQL harden to DevAssist420_Test.html

**Branch:** `xAI/Grok-sync` (base: `Collaboration`)

The full HTML is ~1.6MB (over GitHub Contents API limit for a single tool write). Hardening is applied via the verified patch + script.

## On device / clone (required to land the HTML change)

```sh
git fetch origin
git checkout xAI/Grok-sync
git merge origin/Collaboration   # if needed; resolve conflicts first

# Option A — patch (exact CodeQL fix already verified)
git apply scripts/xai-grok/DevAssist420_Test.codeql-harden.patch

# Option B — script (same result)
python3 scripts/xai-grok/harden_codeql_agent_bridge.py DevAssist420_Test.html

git add DevAssist420_Test.html
git commit -m "security: CodeQL Critical harden on DevAssist420_Test.html (SSRF loopback + deny bridge new Function)"
git push origin xAI/Grok-sync
```

## What changed

1. Loopback-only guard on `WebSocket(CFG.bridgeWsUrl)` and `fetch(CFG.bridgeHttpUrl)`
2. `applyPatch` denies bridge/remote code unless `window._sgOwnerAllowLivePatch === true`
3. `agent_config` allowlist only — no `Object.assign(CFG, msg.config)`

Closes the Critical family: **#588 #589** (injection), **#530 #531** (SSRF) on this file.

## Verify

```sh
grep -n '_sgIsLoopbackUrl\|LIVE_PATCH_DENIED\|Object.assign(CFG,msg.config' DevAssist420_Test.html
# expect: helpers present, LIVE_PATCH_DENIED present, Object.assign line gone
```
