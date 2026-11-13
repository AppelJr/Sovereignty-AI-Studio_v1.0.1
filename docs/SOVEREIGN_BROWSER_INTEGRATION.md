# Sovereign Browser — DuckDuckGo privacy layer

## Integration decision

DuckDuckGo Privacy Extensions is registered as the browser privacy-protection
layer for the Sovereign Browser subsystem. The supplied repository is a browser
extension project, not a standalone browser engine, browser shell, or complete
iOS browser application.

Repository:
- Fork: https://github.com/AppelJr/duckduckgo-privacy-extension
- Upstream: https://github.com/duckduckgo/duckduckgo-privacy-extension
- Declared license: Apache-2.0 (the exact fork license file and redistribution
  obligations still require verification before vendoring or packaging).

The extension README identifies Firefox, Chrome, and Edge builds and documents
Opera compatibility. Safari is a separate project:
https://github.com/duckduckgo/privacy-essentials-safari

## Sovereign integration boundary

```text
HUMAN OWNER
    |
    v
SOVEREIGN BROWSER HOST (not supplied by this repository)
    |
    +---- browser navigation / profile / storage policy
    |
    v
DUCKDUCKGO PRIVACY EXTENSION
    |
    +---- tracker / content privacy signals
    +---- extension UI and user controls
    |
    v
UNTRUSTED PRIVACY EVIDENCE
    |
    v
SOVEREIGN POLICY + GATEONE
    |
    +---- may evaluate evidence
    +---- never grants authority from extension output
```

The extension is not an identity provider, authorization service, provider
router, GateOne replacement, or source of canonical runtime state. Extension
signals are advisory and untrusted until independently evaluated.

## Build and runtime restrictions

The inspected package metadata declares Node.js >=20.16.0 and npm >=10.0.0.
Its build depends on multiple GitHub-hosted packages and build-time scripts.
No dependency installation, extension build, or browser launch was performed
as part of this integration.

Therefore:
- Do not add the extension to the canonical offline startup sequence.
- Do not fetch or install dependencies automatically.
- Do not enable remote extension updates or extension-originated egress in
  LOCAL mode without owner approval and a reviewed policy decision.
- Do not copy upstream source into the canonical runtime.
- Do not claim the Sovereign Browser is operational until a browser host,
  platform packaging, permissions review, and end-to-end tests exist.

## Platform status

| Platform | Current repository capability | Sovereign status |
|---|---|---|
| Firefox | Extension target documented | External; not installed |
| Chrome | Extension target documented | External; not installed |
| Edge | Extension target documented | External; not installed |
| Opera | Chromium-compatible target documented | External; not installed |
| Safari | Separate project required | Blocked pending separate review |
| iOS native browser | Not supplied | Not implemented |

## Required admission gates

1. Pin the fork commit and verify its provenance.
2. Verify the exact license file and all transitive dependency licenses.
3. Review manifest permissions, content scripts, service workers, storage,
   update mechanisms, network destinations, and telemetry behavior.
4. Define a browser-host adapter and profile isolation contract.
5. Define explicit owner approval for installation, updates, and network egress.
6. Add offline policy tests and browser automation tests using isolated profiles.
7. Record the reviewed commit, policy decision, test evidence, and promotion
   decision in durable SCAR before enabling the integration.

Until those gates pass, the component remains
`DECLARED_EXTERNAL_NOT_EXECUTABLE`.
