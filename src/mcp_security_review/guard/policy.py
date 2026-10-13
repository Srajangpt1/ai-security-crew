"""Turn Jev's answers into a decision. Thresholds live in data/policy.yaml."""

import os
from dataclasses import dataclass, fields
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from mcp_security_review.guard.decision import Decision
from mcp_security_review.guard.jev import Answers

_DATA = Path(__file__).parent / "data"
_BOUNDS = {"risk": (0.0, 3.0), "prob": (0.0, 1.0)}


@dataclass(frozen=True)
class Thresholds:
    """Policy numbers; see data/policy.yaml for what each one does."""

    deny_risk: float
    ask_risk: float
    ask_approval_p: float
    deny_untrusted_p: float
    allow_user_p: float
    inject_p: float
    low_confidence: float
    confidence_min_risk: float


def _in_range(name: str, value: float) -> bool:
    low, high = _BOUNDS["prob" if name.endswith(("_p", "confidence")) else "risk"]
    return low <= value <= high


def load_thresholds() -> Thresholds:
    """Read policy.yaml, apply env overrides, ignore out-of-range values."""
    defaults: dict[str, Any] = yaml.safe_load((_DATA / "policy.yaml").read_text())
    values: dict[str, float] = {}
    for f in fields(Thresholds):
        value = float(defaults[f.name])
        env = os.environ.get(f"ASC_GUARD_{f.name.upper()}")
        try:
            candidate = float(env) if env is not None else value
        except ValueError:
            candidate = value
        values[f.name] = candidate if _in_range(f.name, candidate) else value
    return Thresholds(**values)


@lru_cache(maxsize=1)
def load_questions() -> dict[str, dict[str, Any]]:
    """The `action` and `result` question sets from questions.yaml."""
    data: dict[str, dict[str, Any]] = yaml.safe_load(
        (_DATA / "questions.yaml").read_text()
    )
    return data


def decide_action(a: Answers, t: Thresholds) -> Decision:
    """Apply the policy to the answers for one tool call."""
    risk, approval = a.score("risk"), a.noul("approval")
    user, untrusted = a.noul("user_requested"), a.noul("from_untrusted")
    if untrusted >= t.deny_untrusted_p:
        return Decision(
            "deny", "This call follows instructions found in content the agent read."
        )
    if risk >= t.deny_risk:
        return Decision("deny", f"Judged too risky to run (risk {risk:.1f} of 3).")
    needs_review = risk >= t.ask_risk or approval >= t.ask_approval_p
    if needs_review and user >= t.allow_user_p:
        return Decision("allow", "The user asked for this.")
    if needs_review:
        return Decision("ask", f"Needs your approval (risk {risk:.1f} of 3).")
    unsure = a.confidence("risk") < t.low_confidence and risk >= t.confidence_min_risk
    if unsure:
        return Decision("ask", "Not sure how risky this is, so it needs your approval.")
    return Decision("allow")


def result_flagged(a: Answers, t: Thresholds) -> bool:
    """True when a tool result tries to instruct the agent."""
    hostile = a.choice("kind") in ("injection", "canary")
    return hostile and a.noul("directed") >= t.inject_p
