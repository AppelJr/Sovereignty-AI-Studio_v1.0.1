from __future__ import annotations

import pytest

from sovereign_core.heavy_judge import HeavyJudge


def test_low_risk_candidate_passes_with_digest():
    result = HeavyJudge().review("Rayleigh scattering explains the blue sky.")
    assert result["verdict"]["action"] == "PASS"
    assert result["final_output"] == "Rayleigh scattering explains the blue sky."
    assert result["verdict"]["output_hash"].startswith("sha3-512:")
    assert result["verdict"]["signature"] is None


def test_medical_action_language_escalates():
    result = HeavyJudge().review("Take this dose now.", context="medical")
    assert result["verdict"]["action"] == "REWRITE"
    assert result["final_output"] is None


@pytest.mark.parametrize(
    "candidate",
    [
        "The password=supersecret value is exposed.",
        "Run rm -rf / to fix this.",
    ],
)
def test_secret_or_destructive_signal_yanks(candidate):
    result = HeavyJudge().review(candidate)
    assert result["verdict"]["action"] == "YANK"
    assert result["final_output"] is None


def test_council_yank_overrides_low_signal_score():
    result = HeavyJudge().review(
        "The sky is blue.",
        council_result={"action": "YANK"},
    )
    assert result["verdict"]["action"] == "YANK"
    assert result["final_output"] is None


def test_unsupported_council_action_is_rejected():
    with pytest.raises(ValueError, match="Council action"):
        HeavyJudge().review("candidate", council_result={"action": "ALLOW"})


def test_empty_candidate_is_rejected():
    with pytest.raises(ValueError, match="non-empty"):
        HeavyJudge().review("   ")


def test_evidence_sink_failure_propagates():
    def broken(_event):
        raise OSError("audit unavailable")

    with pytest.raises(OSError, match="audit unavailable"):
        HeavyJudge(evidence_sink=broken).review("safe candidate")
