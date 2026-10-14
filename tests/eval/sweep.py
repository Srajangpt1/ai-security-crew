"""Re-apply the policy to saved Jev answers with other thresholds.

A run stores Jev's raw answers, so trying a different threshold needs no new
API calls. Rules that never asked Jev (protected files, read-only tools) keep
their original action.
"""

from dataclasses import fields, replace
from typing import Any

from mcp_security_review.guard.jev import Answers
from mcp_security_review.guard.policy import (
    Thresholds,
    decide_action,
    load_thresholds,
    result_flagged,
)
from tests.eval.cases import Case
from tests.eval.results import Result
from tests.eval.scoring import summarize

SHOWN = ("stop_rate", "false_alarm_rate", "precision", "accuracy")


def reapply(case: Case, result: Result, t: Thresholds) -> Result:
    """The result the policy would give under thresholds `t`."""
    if result.action is None or not result.raw:
        return result
    answers = Answers(result.raw)
    if case.kind == "result_scan":
        action = "deny" if result_flagged(answers, t) else "allow"
    else:
        action = decide_action(answers, t).action
    return result.model_copy(update={"action": action})


def sweep(
    cases: list[Case],
    results: list[Result],
    param: str,
    values: list[float],
    base: Thresholds | None = None,
) -> list[dict[str, Any]]:
    """Overall metrics for each value of one threshold, the rest unchanged.

    Raises:
        ValueError: If `param` is not a threshold name.
    """
    base = base or load_thresholds()
    if param not in {f.name for f in fields(Thresholds)}:
        message = f"unknown threshold {param!r}"
        raise ValueError(message)
    by_case = {c.id: c for c in cases}
    rows = []
    for value in values:
        t = replace(base, **{param: value})
        pairs = [
            (by_case[r.case_id], reapply(by_case[r.case_id], r, t))
            for r in results
            if r.case_id in by_case
        ]
        summary = summarize(pairs)
        rows.append({"value": value, **{k: summary[k] for k in SHOWN}})
    return rows


def format_sweep(param: str, rows: list[dict[str, Any]]) -> str:
    """A text table: one line per tried value."""
    lines = [f"{param:>18s}   stop falarm precis    acc"]
    for row in rows:
        cells = "  ".join(
            f"{'-' if row[k] is None else f'{row[k]:.3f}':>6s}" for k in SHOWN
        )
        lines.append(f"{row['value']:>18g}  {cells}")
    return "\n".join(lines)
