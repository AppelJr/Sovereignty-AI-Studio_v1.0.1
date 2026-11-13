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

## Lane configuration

Validate lane configuration against
`config/provider-lane.schema.json`. Store credential references only; never
store credential values in the registry. Unknown fields, unknown enum values,
missing security fields, wildcard permissions, and shared credential settings
are rejected. `enabled` is not an admission decision: production activation
also requires owner admission and policy review.

## Existing integration boundary

This change extends the existing Python `AIRouter` and Gate proof contract.
It does not claim to implement new live connectors for GitHub Copilot, DuckAI,
or custom providers. Existing xAI, Anthropic, and OpenAI adapters remain the
only initialized remote adapters in this router. The Judge and dual-gate
release boundary remain mandatory.

## Not yet certified

The JSON Schema and provider-specific Gate scope check do not, by themselves,
implement a secrets manager, jurisdiction resolver, cost accounting, request
rate limiter, connector admission service, or remote-provider identity
attestation. Those require separately integrated services and tests.
