# Archived: inactive React frontend source

**Date:** 2026-10-19  
**Authority:** AppelJr (Root direction)  
**Source tip:** Collaboration `eab271c49f13a2f78c7e263ccde73ca27511cfd4`

## What this is

Inactive React / CRA-era source that was **not** part of the active runtime
(see `docs/CLEANUP.md`). Full file bodies remain addressable in git history
at the blob SHAs listed in `MANIFEST.md`.

## Production status

Removed from the production tree:

- `frontend/src/**` (all `.tsx` / `.ts` React sources)
- `frontend/tsconfig.json`
- `frontend/postcss.config.js`

**Retained** (static sovereign frontend):

- `frontend/index.html`, `frontend/dashboard/`, `frontend/runtime/`,
  `frontend/scripts/`, other static HTML panels

## SCAR

Event: `react_src_archived_removed`  
Logged in `scar/scar.jsonl` on this branch.
