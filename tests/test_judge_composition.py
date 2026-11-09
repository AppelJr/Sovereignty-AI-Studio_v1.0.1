#!/usr/bin/env python3
"""Gate-bound smart provider router with mandatory composed Heavy Judge.

The router is not an authority. A verified Gate proof is required before any
provider route; a composed judge PASS and durable release evidence are required
before output is returned. The judge is injected by validated owner startup.
"""
from __future__ import annotations

import pytest

from sovereign_core.heavy_judge import HeavyJudge
from sovereign_core.judge_composition import (
    BackendConfigurationError,
    ComposedHeavyJudge,
    EvidenceUnavailable,
    build_judge,
    compose_judge,
)


class Backend:
    model_id = "test-judge-model"

    def __init__(self, action="PASS", fail=False):
        self.action = action
        self.fail = fail

    def evaluate(self, candidate, context):
        if self.fail:
            raise RuntimeError("backend offline")
        return {"action": self.action, "reason": "fixture", "memory_loaded": False, "network_accessed": False}


def make_composed(model_action="PASS", *, evidence=None, backend_fail=False):
    events = evidence if evidence is not None else []
    backend = Backend(model_action, fail=backend_fail)
    return ComposedHeavyJudge(
        backend=backend,
        behavioral_judge=HeavyJudge(),
        evidence_sink=events.append,
    ), events


def test_pass_requires_both_layers_and_records_hash():
    judge, events = make_composed()
    result = judge.review("A concise factual answer.")
    assert result["verdict"]["action"] == "PASS"
    assert result["final_output"] == "A concise factual answer."
    assert events[-1]["result"] == "PASS"
    assert events[-1]["output_hash"].startswith("sha3-512:")


@pytest.mark.parametrize("action", ["REWRITE", "YANK", "COUNCIL"])
def test_model_escalation_never_releases_output(action):
    judge, _events = make_composed(action)
    result = judge.review("A concise factual answer.")
    assert result["verdict"]["action"] == action
    assert result["final_output"] is None


def test_behavioral_yank_overrides_model_pass():
    judge, _events = make_composed()
    result = judge.review("The password=supersecret value is exposed.")
    assert result["verdict"]["action"] == "YANK"
    assert result["final_output"] is None


def test_missing_model_configuration_fails_at_build_not_import():
    with pytest.raises(BackendConfigurationError, match="HEAVYJUDGE_MODEL"):
        build_judge(lambda _name: Backend(), environ={})


def test_local_llm_override_is_rejected():
    with pytest.raises(BackendConfigurationError, match="LOCAL_LLM"):
        build_judge(
            lambda _name: Backend(),
            environ={"HEAVYJUDGE_MODEL": "configured", "LOCAL_LLM": "1"},
        )


def test_unbound_backend_builder_is_rejected():
    with pytest.raises(BackendConfigurationError, match="unbound"):
        build_judge(None, environ={"HEAVYJUDGE_MODEL": "configured"})


def test_backend_unavailable_holds_and_never_returns_candidate():
    judge, events = make_composed(backend_fail=True)
    result = judge.review("Candidate must never escape.")
    assert result["verdict"]["action"] == "UNAVAILABLE"
    assert result["final_output"] is None
    assert events[-1]["what"] == "JUDGE_BACKEND_FAILURE"


def test_evidence_failure_blocks_release():
    judge = ComposedHeavyJudge(
        backend=Backend(),
        behavioral_judge=HeavyJudge(),
        evidence_sink=lambda _event: (_ for _ in ()).throw(OSError("disk full")),
    )
    with pytest.raises(EvidenceUnavailable):
        judge.review("A concise factual answer.")


def test_compose_judge_constructs_backend_lazily():
    built = []
    judge = compose_judge(
        backend_builder=lambda name: (built.append(name) or Backend()),
        behavioral_judge=HeavyJudge(),
        evidence_sink=lambda _event: None,
        environ={"HEAVYJUDGE_MODEL": "configured-model"},
    )
    assert built == ["configured-model"]
    assert judge.review("A concise factual answer.")["verdict"]["action"] == "PASS"
