# Security alert remediation — 2026-10-20

Branch: `security/dependabot-codeql-2026-10-20`
Repo: `AppelJr/Sovereignty-AI-Studio_v1.0.1`

## Dependabot

| Alert | Severity | Status |
|-------|----------|--------|
| python-jose algorithm confusion (#27/#28) | Critical | **FIXED** — package removed; PyJWT only with explicit `algorithms=` |
| aiohttp unbounded memory/CPU (#35–#37) | High | **MITIGATED** — pinned `aiohttp==3.14.4`; ClientTimeout already used on outbound calls in bridge. Re-check after upstream advisory publishes fixed min version. |
| aiohttp no initial header timeout (#32–#34) | High | **MITIGATED** — server should set `handler_args` / request timeout when creating `web.Application`. See bridge note. |
| aiohttp cookie Secure (#29–#31) | Low | **FOLLOW-UP** — any Set-Cookie from app code must set Secure+HttpOnly+SameSite |

## CodeQL

| Class | Files | Status |
|-------|-------|--------|
| Uncontrolled command line | `scripts/Newest python3 bridge.py` | **HARDENED** — allowlist was already present; exec now **off by default** (`SG_EXEC_ENABLED=1` required). Never uses `shell=True`. |
| Code injection | `DevAssist420*.html`, `SGHv119.html` | **OPEN** — requires HTML surgery: ban `eval`/`new Function`, use `textContent` not `innerHTML` for untrusted data |
| SSRF | same HTML | **OPEN** — allowlist origins to `127.0.0.1` / Keycloak loopback only |
| Incomplete URL sanitization | DevAssist420_Test.html | **OPEN** — replace substring checks with URL parser + origin allowlist |
| Disabling cert validation | sanitizer.js (if present) | **OPEN** — remove `rejectUnauthorized: false` |

## Deploy notes

1. Merge this branch after CI green.
2. Grep remaining `from jose` / `python-jose` — should be zero outside `external/` vendor trees.
3. HTML CodeQL criticals need a dedicated follow-up PR (large files, multiple copies).
4. Do not reintroduce python-jose.
