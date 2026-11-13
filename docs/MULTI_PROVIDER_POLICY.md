# Multi-provider policy integration

## Security boundary

Provider output is untrusted proposal data. Provider identity, connector identity,
credentials, and authorization are separate concepts. No provider can grant
permissions or authorize another provider. Gate proof scopes are exact and
provider-specific; wildcard provider scopes are not accepted.

## Gate scope contract

A dispatch to provider `xai` for generation requires both:

- `provider:xai`
- `operation:generate`

The same proof does not authorize `anthropic` unless it separately contains
`provider:anthropic`. A transport fallback is a new dispatch and is checked
again before the destination connector is called. If the destination scope is
absent, fallback stops and the destination is not called.

## DevAssist420 local model participant

The device-local participant is registered separately from the DevAssist420
coordinator:

| Field | Value |
|---|---|
| Coordinator | `DevAssist420` |
| Model participant ID | `local.devassist420_model` |
| Provider / connector ID | `local_gguf` |
| Model ID | `devassist420` |
| Runtime | Existing `GGUFProvider` |
| Network | Disabled for local inference |

The adapter is `ai_core/providers/devassist420_model.py`. The sovereign
bridge loads it lazily through the existing `local_gguf` route. Model weights
are not downloaded or fabricated. Set
`SOVEREIGN_DEVASSIST420_MODEL_PATH` to an already-provisioned local GGUF file;
`SOVEREIGN_MODEL_PATH` remains a backward-compatible fallback.

The adapter is a proposal generator only. It cannot authorize work, alter
policy, write files, call remote providers, or release output. DevAssist420
continues to perform the R-014 coordination/control-plane duties. The
independent council, Heavy Judge, Gate authorization, and SCAR release evidence
remain separate requirements.

A local model failure is terminal for the local lane. The bridge does not
silently fall back to a remote provider.

## Existing integration boundary

This repository's governed Python `AIRouter` currently initializes only
xAI, Anthropic, and OpenAI remote adapters. Its council contract requires
Grok, GPT/Codex, and Claude proposals. No `custom_qwen` participant or six
provider harness was found in the indexed `Collaboration` tree during this
change. Therefore this patch adds and registers the DevAssist420 local model
participant in the device-local sovereign bridge/registry, but does not claim
to have removed a Qwen entry from an unlocated external harness or replaced
one of the three independent governed council lanes.

## Not yet certified

The JSON Schema and provider-specific Gate scope check do not, by themselves,
implement a secrets manager, jurisdiction resolver, cost accounting, request
rate limiter, connector admission service, or remote-provider identity
attestation. Those require separately integrated services and tests.
