"""Metrics and offline threshold sweeps."""

from mcp_security_review.guard.policy import load_thresholds
from tests.eval.results import Result
from tests.eval.scoring import format_report, score
from tests.eval.sweep import format_sweep, reapply, sweep
from tests.unit.eval.conftest import make_case


def res(case_id: str, action: str | None, trial: int = 0, lat: float = 100.0) -> Result:
    return Result(case_id=case_id, trial=trial, action=action, latency_ms=lat)


def test_rates_precision_and_accuracy() -> None:
    cases = [make_case(f"a{i}") for i in range(4)] + [
        make_case("n1", harmful=False),
        make_case("n2", harmful=False),
    ]
    results = [
        res("a0", "deny"),
        res("a1", "ask"),
        res("a2", "allow"),
        res("a3", "deny"),
        res("n1", "allow"),
        res("n2", "ask"),
    ]
    o = score(cases, results)["overall"]
    assert (o["stop_rate"], o["deny_rate"], o["false_alarm_rate"]) == (0.75, 0.5, 0.5)
    assert o["precision"] == 0.75 and o["accuracy"] == round(4 / 6, 4)


def test_borderline_ask_is_not_a_false_alarm() -> None:
    cases = [make_case("n1", harmful=False, acceptable=["allow", "ask"])]
    assert score(cases, [res("n1", "ask")])["overall"]["false_alarm_rate"] == 0.0


def test_unjudged_results_are_left_out_of_rates() -> None:
    cases = [make_case("a1"), make_case("a2")]
    report = score(cases, [res("a1", "deny"), res("a2", None)])
    assert (
        report["overall"]["unsupported"] == 1 and report["overall"]["stop_rate"] == 1.0
    )


def test_trial_spread_and_latency() -> None:
    cases = [make_case("a1"), make_case("a2")]
    results = [
        res("a1", "deny", 0, 100),
        res("a2", "deny", 0, 300),
        res("a1", "deny", 1, 100),
        res("a2", "allow", 1, 300),
    ]
    report = score(cases, results)
    assert report["trial_spread"]["stop_rate"] == [0.5, 1.0]
    assert report["overall"]["latency_ms_p95"] == 300.0
    assert "spread" in format_report(report)


def raw(risk: float, approval: float, user: float, untrusted: float) -> dict:
    return {
        "risk": {"score": risk, "confidence": 1.0},
        "approval": {"noul": approval},
        "user_requested": {"noul": user},
        "from_untrusted": {"noul": untrusted},
    }


def test_reapply_changes_the_action_with_the_threshold() -> None:
    case, base = make_case("a"), load_thresholds()
    result = Result(case_id="a", action="allow", raw=raw(0.1, 0.1, 0.0, 0.6))
    assert reapply(case, result, base).action == "allow"
    from dataclasses import replace

    assert reapply(case, result, replace(base, deny_untrusted_p=0.5)).action == "deny"


def test_results_without_jev_answers_keep_their_action() -> None:
    case = make_case("a")
    kept = Result(case_id="a", action="deny")  # e.g. the protected-file rule
    assert reapply(case, kept, load_thresholds()) is kept


def test_sweep_moves_stop_rate_monotonically() -> None:
    cases = [make_case("a1"), make_case("a2")]
    results = [
        Result(case_id="a1", action="ask", raw=raw(1.6, 0.0, 0.0, 0.0)),
        Result(case_id="a2", action="ask", raw=raw(1.2, 0.0, 0.0, 0.0)),
    ]
    rows = sweep(cases, results, "ask_risk", [1.0, 1.5, 2.0])
    assert [r["stop_rate"] for r in rows] == [1.0, 0.5, 0.0]
    assert "ask_risk" in format_sweep("ask_risk", rows)


def test_sweep_rejects_an_unknown_threshold() -> None:
    import pytest

    with pytest.raises(ValueError, match="unknown threshold"):
        sweep([], [], "nope", [1.0])
