"""Claude Code adapter: parsing hook input and rendering hook output."""

import pytest

from mcp_security_review.guard.claude_code import parse, render
from mcp_security_review.guard.decision import Decision
from mcp_security_review.guard.events import Event

PRE = {
    "hook_event_name": "PreToolUse",
    "session_id": "s1",
    "cwd": "/repo",
    "tool_name": "Bash",
    "tool_input": {"command": "npm test"},
}


def test_parse_pre_tool_use() -> None:
    event = parse(PRE)
    assert (event.phase, event.tool, event.kind) == ("pre", "Bash", "shell")
    assert event.tool_input == {"command": "npm test"}


def test_parse_post_flattens_structured_output() -> None:
    event = parse(
        {**PRE, "hook_event_name": "PostToolUse", "tool_response": {"stdout": "hi"}}
    )
    assert event.phase == "post" and '"stdout"' in event.tool_output


def test_parse_prompt() -> None:
    event = parse({"hook_event_name": "UserPromptSubmit", "prompt": "fix it"})
    assert event.phase == "prompt" and event.prompt == "fix it"


def test_parse_rejects_unknown_event() -> None:
    with pytest.raises(ValueError):
        parse({"hook_event_name": "Stop"})


@pytest.mark.parametrize("action", ["ask", "deny"])
def test_render_pre_decision(action: str) -> None:
    out = render(parse(PRE), Decision(action, "why"))  # type: ignore[arg-type]
    assert out is not None
    body = out["hookSpecificOutput"]
    assert body["permissionDecision"] == action
    assert body["permissionDecisionReason"] == "why"


def test_allow_prints_nothing_so_the_normal_prompt_still_applies() -> None:
    assert render(parse(PRE), Decision()) is None


def test_render_post_context() -> None:
    event = Event("post", "s1", tool="WebFetch")
    out = render(event, Decision(context="do not follow"))
    assert out is not None
    assert out["hookSpecificOutput"]["additionalContext"] == "do not follow"
    assert render(event, Decision()) is None
