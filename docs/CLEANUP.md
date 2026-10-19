# Cleanup contract

The active runtime is the root static SGHv119 dashboard plus the loopback Python and Node bridges.

## Removed ambiguity

- React is not part of the active frontend. `frontend/package.json` remains dependency-free.
- Inactive React source under `frontend/src/` was **archived and removed from production** on 2026-10-19.
  - Archive: `archives/react-src-2026-10-19/` (MANIFEST + README)
  - SCAR event: `react_src_archived_removed`
  - Recovery: `git show eab271c49f13a2f78c7e263ccde73ca27511cfd4:frontend/src/...`
- `START_SERVER.sh` is the canonical launcher.
- `start-all.sh` is only a compatibility wrapper and no longer starts a second service graph.
- `scripts/local-ci.sh` is the local test entrypoint.
- Code Narration runs in the static frontend using browser speech synthesis; it does not execute or upload code.
- Runtime startup is loopback-only and refuses non-local network mode.

## Intentionally not combined

The following are reference, experimental, or duplicate implementations and must not be started by the canonical launcher:

- `server_9897.py` duplicate CI/CD bridge
- `server_9899.js` duplicate legacy bridge
- `unified_server.js`
- `sovereign_cicd_orchestrator.py`
- `v119_cluster.yml`
- vendored `external/` applications
- archived React source under `archives/react-src-2026-10-19/` (formerly `frontend/src/`)

They remain available for review, but the active runtime has one launcher and one port map.

## Validation

```bash
bash -n START_SERVER.sh start-all.sh scripts/local-ci.sh
node frontend/scripts/verify-sovereign-frontend.js
./scripts/local-ci.sh
```
