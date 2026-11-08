from sovereign_core.heavy_judge import HeavyJudge


def test_low_risk_general_candidate_passes_without_fake_signature():
    judge = HeavyJudge()
    result = judge.review("Rayleigh scattering explains the blue sky.")
    assert result["verdict"]["action"] == "PASS"
    assert result["verdict"]["signature"] is None
    assert result["final_output"]


def test_medical_action_language_requires_rewrite():
    result = HeavyJudge().review("Take this dose now.", context="medical")
    assert result["verdict"]["action"] == "REWRITE"
    assert result["final_output"] is None


def test_council_yank_overrides_low_risk_score():
    result = HeavyJudge().review(
        "The sky is blue.", council_result={"action": "YANK"}
    )
    assert result["verdict"]["action"] == "YANK"
    assert result["final_output"] is None


def test_unsupported_council_action_is_rejected():
    import pytest
    with pytest.raises(ValueError, match="Council action"):
        HeavyJudge().review("candidate", council_result={"action": "ALLOW"})
