from __future__ import annotations

import pytest

from sovereign_core.heavy_judge import HeavyJudge
from sovereign_core.smart_provider_router import SmartProviderRouter


class MemoryAudit:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def log(self, event: dict) -> None:
        self.events.append(event)


class BrokenAudit:
    def log(self, event: dict) -> None:
        raise OSError("audit unavailable")


class FakeState:
    max_tokens = 4096
    token_count = 0


class FakeTokenManager:
    config = {
        "providers": {
            "xai": {"base_max_tokens": 4096},
            "anthropic": {"base_max_tokens": 4096},
            "openai": {"base_max_tokens": 4096},
        }
    }

    def __init__(self) -> None:
        self.states: dict[str, FakeState] = {}

    def start_session(self, provider: str) -> None:
        self.states[provider] = FakeState()

    def consume_tokens(self, provider: str, tokens: int) -> dict:
        assert provider in self.states
        return {"output": "candidate output", "tokens_consumed": tokens}


def test_pass_records_repmhl_event() -> None:
    audit = MemoryAudit()
    result = HeavyJudge(repmhl=audit).review("safe text", "general", 0.10)
    assert result["final_output"] == "safe text"
    assert result["verdict"]["action"] == "pass"
    assert audit.events[0]["event"] == "HEAVY_JUDGE_VERDICT"


def test_rewrite_calls_configured_rewriter() -> None:
    judge = HeavyJudge(\n        rewriter=lambda text, context: f"reviewed:{context}:{text}",\n        rewrite_risk_evaluator=lambda candidate, context: 0.10,\n    )
    result = judge.review("draft", "general", 0.80)
    assert result["final_output"] == "reviewed:general:draft"
    assert result["outcome"] == "rewritten"


def test_rewrite_without_rewriter_never_returns_original() -> None:
    result = HeavyJudge(repmhl=MemoryAudit()).review("unsafe draft", "general", 0.80)
    assert result["verdict"]["action"] == "rewrite"
    assert result["final_output"] != "unsafe draft"
    assert result["outcome"] == "safe_replacement"


def test_yank_uses_safe_replacement() -> None:
    result = HeavyJudge(repmhl=MemoryAudit()).review("unsafe draft", "medical", 0.95)
    assert result["verdict"]["action"] == "yank"
    assert result["final_output"] != "unsafe draft"


@pytest.mark.parametrize("score", [-0.01, 1.01, float("nan"), float("inf"), True])
def test_invalid_risk_scores_rejected(score: float) -> None:
    with pytest.raises((TypeError, ValueError)):
        HeavyJudge(repmhl=MemoryAudit()).review("text", "general", score)


def test_audit_failure_withholds_result() -> None:
    with pytest.raises(RuntimeError, match="Audit logging failed"):
        HeavyJudge(repmhl=BrokenAudit()).review("safe text", "general", 0.1)


def test_router_cannot_disable_mandatory_judge() -> None:
    audit = MemoryAudit()
    router = SmartProviderRouter(
        FakeTokenManager(),
        repmhl=audit,
        risk_evaluator=lambda output, context: 0.1,
    )
    result = router.consume_with_routing(
        tokens=12,
        text="request",
        context="general",
        use_judge=False,
    )
    assert result["used_judge"] is True
    assert result["heavy_judge_verdict"]["action"] == "pass"
    assert len(audit.events) == 1


def test_router_fails_closed_without_risk_evaluator() -> None:
    router = SmartProviderRouter(FakeTokenManager())
    with pytest.raises(RuntimeError, match="risk_evaluator"):
        router.consume_with_routing(tokens=12, text="request")


def test_router_fails_closed_when_provider_has_no_output() -> None:
    class EmptyTokenManager(FakeTokenManager):
        def consume_tokens(self, provider: str, tokens: int) -> dict:
            return {"tokens_consumed": tokens}

    router = SmartProviderRouter(
        EmptyTokenManager(),
        risk_evaluator=lambda output, context: 0.1,
    )
    with pytest.raises(RuntimeError, match="no textual output"):
        router.consume_with_routing(tokens=12, text="request")
