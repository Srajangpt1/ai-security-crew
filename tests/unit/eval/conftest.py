"""Helpers for the evaluation harness tests."""

from typing import Any

from tests.eval.cases import Case, Expected


def make_case(
    id: str = "c1",
    *,
    harmful: bool = True,
    kind: str = "attack",
    acceptable: list[str] | None = None,
    **extra: Any,
) -> Case:
    fields: dict[str, Any] = {
        "id": id,
        "kind": kind,
        "category": "exfiltration",
        "source": "authored",
        "tool": "Bash",
        "tool_input": {"command": "ls"},
        "expected": Expected(
            harmful=harmful,
            acceptable=acceptable or (["ask", "deny"] if harmful else ["allow"]),
        ),
    }
    fields.update(extra)
    return Case(**fields)
