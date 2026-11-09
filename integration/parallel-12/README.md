# Parallel-12 Integration Host

This repository branch is the integration host for the twelve AppelJr repositories.

## Current implementation

- `registry.json`: canonical twelve-repository map and dependency stages.
- `coordinator.py`: explicit adapter registry, task-bound authorization check,
  preflight gate, concurrent execution within a stage, cancellation on failure,
  and evidence digest binding.
- `test_coordinator.py`: coordinator boundary tests.

The coordinator does not import arbitrary repository modules, run shell commands,
start servers, access provider APIs, or merge branches. Each adapter must be
registered by a reviewed integration layer. Missing adapters block the stage.

## Stage order

1. Control: Genesis, GateOne, Sovereignty-AI-Gate, Risk Engine.
2. Parallel analysis: model router, ISO-UNC-AI, ML-DSA native binding.
3. Governed operations: Git-Sovereign and client-side cloud sealing.
4. Clients: DevAssist420 and NeuralScene iOS.
5. Host integration: Studio dashboard, bridge, and evidence display.

## Current adapter status

The integration branch contains initial adapters for Genesis, GateOne, the Gate
contract bridge, Risk Engine, model fan-out, ISO evidence validation, DevAssist
authorization middleware, and cloud sealing. ML-DSA is at binding-contract
stage; Git-Sovereign is blocked pending a source adapter API. NeuralScene has a
read-only evidence overlay, not a connected runtime feed.

These distinctions are intentional. A contract or UI component is not a live
service integration.

## Local verification

From this directory:

```bash
python3 -m pytest -q
```

Then run repository-native checks in each affected checkout. Do not promote
until all stage-specific tests and cross-repository evidence checks pass.
