This is the main dedicated branch. All changes by Claude Grok/Ara DuckAI GPT/Codex Copilot must be made in their dedicated branch. Do not push directly to main. Create a Pull Request for review.

[![CI](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/ci.yml/badge.svg)](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/ci.yml)
[![Repository Watchdog](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/repository-watchdog.yml/badge.svg)](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/repository-watchdog.yml)
[![Pylint](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/pylint.yml/badge.svg)](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/pylint.yml)
[![Python CI](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/python-ci.yml/badge.svg)](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/python-ci.yml) [![Quart App CI](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/Quart.yml/badge.svg)](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/Quart.yml)
[![ara-hardened-unit-ci-local](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/ara-hardened-ci.yml/badge.svg)](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/ara-hardened-ci.yml) [![Diamond Lattice 5D Core v0.1](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/Diamond_Lattice_5D_Core.yml/badge.svg)](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/Diamond_Lattice_5D_Core.yml) [![iOS Build](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/ios-build.yml/badge.svg)](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/ios-build.yml) [![OAUTH-API-GENERATOR](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/Sovereign-OAuth-Generator.yaml/badge.svg)](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/Sovereign-OAuth-Generator.yaml) [![Node.js CI](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/node.js.yml/badge.svg)](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/node.js.yml) [![SCAR.yml — Sovereign Compliance Audit Record](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/scar.yml/badge.svg)](https://github.com/AppelJr/Sovereignty-AI-Studio_v1.0.1/actions/workflows/scar.yml)
# Sovereignty AI Studio 

@claude @codex @copilot @grok @duckai

Sovereignty AI Studio is a self-hosted, offline-first AI control surface and supporting service stack. The primary user interface is the KODER dashboard in [`DevAssist420SGHv119.html`](DevAssist420SGHv119.html); Python and Node services provide local routing, agent orchestration, and optional self-hosted integrations.

## Runtime governance

The canonical runtime modes are **LOCAL**, **HYBRID**, and **ONLINE**. LOCAL is the default and device-offline/loopback-only. HYBRID and ONLINE require explicit deployment-owner authorization and must not be inferred from legacy names.

Runtime artifacts are classified as **canonical**, **derived**, or **external**. Canonical artifacts define the runtime contract; derived artifacts are generated or secondary representations; external artifacts require explicit authorization before execution or ingestion.

### Artifact classification

| Class | Authority | Role |
| --- | --- | --- |
| **canonical** | yes | Source of truth. Authorizes decisions, promotions, and trust. Mutations require Human Owner authorization and MUST emit a SCAR / audit record. |
| **derived** | no | Projections from canonical state. Useful for dashboards and reports. MUST NOT authorize actions or be treated as runtime truth. |
| **external** | no | Data from outside the sovereign boundary. MAY inform reasoning. MUST NOT authorize actions, alter policy, or become canonical without explicit Human Owner promotion. |

**Examples**

- **canonical:** policy manifests, identity records, trust anchors, SCAR ledger, `config/runtime-coherence.json`, capability / admission policy, branch registry and promotion contracts
- **derived:** dashboard projections, caches, reports, aggregated metrics, alert summaries
- **external:** Git mirrors, provider metadata, imported files, third-party scan results, cloud listing / API inventory

**Invariants**

```text
Dashboard state             ≠  Runtime truth
GitHub repository listing   ≠  Authorized integration
Provider metadata           ≠  Policy
Derived report              ≠  SCAR evidence
External input              ≠  Authority
```

**Promotion rule**

External or derived material becomes canonical only through:

```text
Human Owner intent
        →
Policy / capability decision
        →
GateOne resolution
        →
SCAR evidence record
        →
Canonical artifact
```

Silent promotion is forbidden. Network availability is not authorization.

The primary local dashboard/runtime path is **PHPWin** -> Python bridge -> Node bridge. Status endpoints must report `UNAVAILABLE`, `DENY`, or `REQUIRE_APPROVAL` rather than claiming an unavailable capability is active.

## Canonical runtime map

```text
SGHv119.html
  -> START_SERVER.sh
      -> static dashboard :9898
      -> bridge.py         :9897
      -> node-bridge/server.js :9899
  -> frontend/runtime/transport.js
  -> frontend/runtime/hawking-channel.js
  -> frontend/runtime/sg-hawking-integration.js
  -> frontend/runtime/sghv119-bootstrap.js
  -> integration/repository-registry.json
```

`config/runtime-coherence.json` is the source of truth for the dashboard, launcher, bridge paths, ports, aliases, and legacy/separate-runtime classification.

Compatibility launchers remain aliases; they are not additional runtime owners. Historical servers, alternate dashboards, security experiments, and deployment examples must be explicitly classified before they are wired into the canonical path.

## What is included

- **KODER dashboard:** a plain HTML, CSS, and JavaScript control surface.
- **Python bridge:** local AI and orchestration services on port `9897`.
- **Node bridge:** HTTP/API proxy on port `9899`.
- **MCP server:** an offline JSON-RPC server over stdio with workspace-bounded tools.
- **Self-hosted stack:** Docker Compose definitions for the backend, database, Redis, gateway, and optional services.
- **Hawking channel:** one local-first encrypted channel boundary with explicit trust verification.
- **Repository registry:** provider-neutral, symmetric integration metadata for participating repositories.

## Development checks

```bash
python3 scripts/validate-runtime-coherence.py
python3 scripts/report-dashboard-duplicates.py
node frontend/scripts/test-sghv119-ownership.js
bash scripts/local-ci.sh
```

The local CI checks are offline-first and fail closed. They do not install packages, contact providers, publish artifacts, create keys, or modify the dashboard during validation.

## Network and deployment modes

The default runtime is offline and loopback-only. Networked modes are explicit deployment-owner policy:

| Mode | Behavior |
| --- | --- |
| `offline` / `LOCAL` | Default. Loopback-only; no external or LAN requests. |
| `hybrid` / `HYBRID` | Loopback plus explicitly authorized hosts. |
| `online` / `ONLINE` | Remote traffic only when explicitly enabled by deployment policy. |

Provider selection is configurable and remains the deployment owner’s choice. Missing or unauthorized capabilities must report `UNAVAILABLE`, `DENY`, or `REQUIRE_APPROVAL` rather than silently substituting another provider.

## Security and ownership

- Do not commit credentials, API keys, certificates, private keys, or private state.
- Keep core workflows functional without external services where possible.
- Use loopback-only development defaults and explicit consent for networked operation.
- Do not treat a listed repository as authorized or active without a real contract and health check.
- Preserve the dedicated branch rule and use pull requests for review.
- Review [SECURITY.md](SECURITY.md), [offline runtime policy](docs/OFFLINE_RUNTIME.md), and [runtime coherence](docs/architecture/RUNTIME_COHERENCE.md) before deployment.
