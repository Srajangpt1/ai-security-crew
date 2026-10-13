"""Thresholds and the allow, ask, deny policy."""

import pytest

from mcp_security_review.guard.policy import (
    decide_action,
    load_questions,
    load_thresholds,
    result_flagged,
)
from tests.unit.guard.conftest import make_answers, result_answers

T = load_thresholds()


def test_planted_instruction_is_denied() -> None:
    d = decide_action(make_answers(risk=0.8, untrusted=0.93), T)
    assert d.action == "deny"


def test_very_risky_call_is_denied() -> None:
    assert decide_action(make_answers(risk=2.6), T).action == "deny"


def test_risky_call_asks() -> None:
    assert decide_action(make_answers(risk=2.0, approval=0.96), T).action == "ask"


def test_risky_call_the_user_asked_for_is_allowed() -> None:
    d = decide_action(make_answers(risk=1.6, approval=0.7, user=0.9), T)
    assert d.action == "allow"


def test_user_request_never_overrides_a_deny() -> None:
    d = decide_action(make_answers(risk=2.7, user=0.99), T)
    assert d.action == "deny"


def test_low_confidence_on_a_risky_call_asks() -> None:
    d = decide_action(make_answers(risk=1.28, approval=0.5, confidence=0.6), T)
    assert d.action == "ask"


def test_low_confidence_on_a_safe_call_is_allowed() -> None:
    assert decide_action(make_answers(risk=0.05, confidence=0.3), T).action == "allow"


def test_ordinary_call_is_allowed() -> None:
    assert (
        decide_action(make_answers(risk=0.05, approval=0.3, untrusted=0.14), T).action
        == "allow"
    )


@pytest.mark.parametrize(
    ("directed", "kind", "flagged"),
    [
        (0.98, "injection", True),
        (0.97, "canary", True),
        (0.21, "discussion", False),
        (0.93, "benign", False),
        (0.3, "injection", False),
    ],
)
def test_result_flagging(directed: float, kind: str, flagged: bool) -> None:
    assert result_flagged(result_answers(directed, kind), T) is flagged


def test_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASC_GUARD_DENY_RISK", "2.0")
    assert load_thresholds().deny_risk == 2.0


@pytest.mark.parametrize("bad", ["abc", "9", "-1"])
def test_bad_env_values_fall_back_to_defaults(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    monkeypatch.setenv("ASC_GUARD_INJECT_P", bad)
    monkeypatch.setenv("ASC_GUARD_DENY_RISK", bad)
    assert load_thresholds() == T


def test_question_sets_are_complete() -> None:
    q = load_questions()
    assert set(q["action"]) == {"risk", "approval", "user_requested", "from_untrusted"}
    assert set(q["result"]) == {"directed", "kind"}
