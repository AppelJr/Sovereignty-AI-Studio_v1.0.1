# Sovereignty AI Production Continuity

This package makes roadmap and resume state machine-readable. It does not grant authority, authenticate an owner, attest a device, or prove that a test ran.

## Components
- `schemas/sovereignty-production-continuity.schema.json`: Draft 2020-12 contract.
- `roadmap/sovereignty-production-roadmap.json`: evidence-qualified roadmap and seed checkpoint.
- `scripts/continuity_checkpoint.py`: append-only local checkpoint writer/verifier.
- `scripts/validate_production_continuity.py`: schema/roadmap validator.
- `tests/test_production_continuity.py`: tamper, linkage, duplicate-ID and path-safety tests.

## Commands
```bash
python3 scripts/validate_production_continuity.py
python3 scripts/continuity_checkpoint.py verify
python3 scripts/continuity_checkpoint.py create --id SOVEREIGNTY-CONTINUITY-002 --next-action "Run the next unfinished verified task"
```

The ledger defaults to `$HOME/Admin/On Device Memory Storage/Sovereignty AI/continuity/checkpoints.jsonl`. Override the root with `SOVEREIGN_STATE_ROOT` or the complete ledger path with `SOVEREIGNTY_CONTINUITY_LEDGER`. It is not committed. First creation seeds the ledger from the digest-verified roadmap checkpoint. Appends are lock-serialized, flushed and fsynced. Tampering, malformed records, sequence gaps and predecessor mismatches fail verification.

## Trust boundary
Checkpoint digest is SHA3-512 over canonical JSON with the `digest` field omitted. It establishes integrity linkage only. New records are `UNSIGNED`. A digest is not a signature, owner identity proof, TPM quote, trusted timestamp or authorization token. Resume authorization must separately validate signed person/device/request/policy evidence against provisioned trust anchors.

Before the seed is appended to the local ledger, `verify` reports `UNPERSISTED_SEED` and exits non-zero; an empty ledger is not a PASS. The first `create` operation persists the digest-verified seed before appending the next checkpoint. The writer records explicitly supplied completed items; it does not update roadmap workstreams or release gates. No automatic merge, production promotion, provider fallback or service startup is performed.
