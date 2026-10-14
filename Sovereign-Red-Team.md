---
title: Sovereign Red Team
version: 0.1.0
provenance:
  author: Appel420/AppelJr
  created: 2026-09-14T11:39Z
  source: Grok (xAI) execution under owner authorization
---

# Sovereign Red Team Skill

Owner-gated break/fix loop.

## Gates

1. **Discuss** — propose attack, scope, blast radius. No execution.
2. **Approve** — owner taps green. Action authorized.
3. **Deny** — owner taps red. Action blocked, logged.
4. **Execute** — only after approve. Signed, scoped, scar-logged.

## Detection

Mismatch between attested scope and actual action = fraud signal. Logged, attributed, never erased.

## Zero rules

- No anonymous testing.
- No credential abuse.
- No wiping records (except need-to-know erasure with sealed receipt).
- No bypassing the owner gate.
