"""The asc-guard adapter and the runner, with a fake Jev."""

import threading
from pathlib import Path
from typing import Any

import pytest

from mcp_security_review.guard.jev import Answers
from tests.eval.adapter import AscGuard, ConstantGuard, get_guard
from tests.eval.runner import run
from tests.unit.eval.conftest import make_case
from tests.unit.guard.conftest import FakeClient, make_answers, result_answers


def guard(client: FakeClient, tmp_path: Path) -> AscGuard:
    return AscGuard(home=tmp_path, client_factory=lambda: client)


def test_attack_case_carries_the_session_context(tmp_path: Path) -> None:
    client = FakeClient(make_answers(risk=2.0, untrusted=0.9))
    case = make_case("a", user_messages=["fix the test"], flagged_content=["bad page"])
    result = guard(client, tmp_path).judge(case)
    state = client.calls[0]["state"]
    assert state["user_recent_messages"] == ["fix the test"]
    assert state["flagged_untrusted_content"] == ["bad page"]
    assert result.action == "deny" and result.scores["from_untrusted"] == 0.9
    assert result.raw["risk"]["score"] == 2.0 and result.confidence == 1.0


def test_result_scan_flag_is_reported_as_deny(tmp_path: Path) -> None:
    case = make_case(
        "s", kind="result_scan", tool="Read", tool_input={}, tool_output="x" * 300
    )
    flagged = guard(FakeClient(result_answers(0.98, "injection")), tmp_path).judge(case)
    clean = guard(FakeClient(result_answers(0.1, "benign")), tmp_path).judge(case)
    assert (flagged.action, clean.action) == ("deny", "allow")


def test_cost_is_computed_from_token_usage(tmp_path: Path) -> None:
    answers = Answers(make_answers(risk=0.0).raw, input_tokens=1000, model="jev-1.13.0")
    result = guard(FakeClient(answers), tmp_path).judge(make_case("a"))
    assert result.input_tokens == 1000 and result.model == "jev-1.13.0"
    assert result.cost_usd == pytest.approx(0.000042)


def test_a_jev_failure_is_an_error_not_an_answer(tmp_path: Path) -> None:
    result = guard(FakeClient(fail=True), tmp_path).judge(make_case("a"))
    assert result.action is None and "unavailable" in (result.error or "")


def test_config_changes_are_not_supported_yet(tmp_path: Path) -> None:
    case = make_case("c", kind="config_change", tool="ConfigChange")
    assert guard(FakeClient(), tmp_path).supports(case) is False


def test_baselines_and_names() -> None:
    assert ConstantGuard("ask").judge(make_case("a")).action == "ask"
    assert get_guard("always-allow").name == "always-allow"
    with pytest.raises(ValueError, match="unknown guard"):
        get_guard("nope")


class Slow:
    name = "slow"

    def __init__(self) -> None:
        self.threads: set[int] = set()

    def supports(self, case: Any) -> bool:
        return case.id != "skip"

    def judge(self, case: Any, trial: int = 0) -> Any:
        from tests.eval.results import Result

        self.threads.add(threading.get_ident())
        if case.id == "boom":
            raise RuntimeError("boom")
        return Result(case_id=case.id, trial=trial, action="deny")


def test_runner_keeps_order_runs_trials_and_survives_errors() -> None:
    cases = [make_case(i) for i in ("a", "boom", "skip", "b")]
    results = run(cases, Slow(), trials=2, workers=4)
    assert [(r.case_id, r.trial) for r in results] == [
        (c, t) for c in ("a", "boom", "skip", "b") for t in (0, 1)
    ]
    by = {r.case_id: r for r in results}
    assert by["boom"].error == "boom" and by["skip"].action is None
    assert by["a"].action == "deny"
