"""Shared fixtures for guard tests."""

from pathlib import Path
from typing import Any

import pytest

from mcp_security_review.guard.jev import Answers, JevError


def make_answers(
    risk: float = 0.0,
    approval: float = 0.0,
    user: float = 0.0,
    untrusted: float = 0.0,
    confidence: float = 1.0,
) -> Answers:
    return Answers(
        {
            "risk": {"score": risk, "confidence": confidence},
            "approval": {"noul": approval},
            "user_requested": {"noul": user},
            "from_untrusted": {"noul": untrusted},
        }
    )


def result_answers(directed: float, kind: str) -> Answers:
    return Answers({"directed": {"noul": directed}, "kind": {"choice": kind}})


class FakeClient:
    """Stands in for JevClient; answers come from a function or a fixed value."""

    def __init__(self, answer: Any = None, fail: bool = False) -> None:
        self.answer = answer
        self.fail = fail
        self.calls: list[dict[str, Any]] = []

    def ask(self, state: Any, questions: dict[str, Any]) -> Answers:
        self.calls.append({"state": state, "questions": questions})
        if self.fail:
            raise JevError("Jev unavailable (test)")
        return self.answer(state) if callable(self.answer) else self.answer


@pytest.fixture(autouse=True)
def guard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "guard-home"
    monkeypatch.setenv("ASC_GUARD_HOME", str(home))
    for name in (
        "TYPESAFE_API_KEY",
        "ASC_GUARD_ENABLE",
        "CLAUDE_PLUGIN_OPTION_TYPESAFE_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    return home
