"""Cursor adapter: parsing hook input and rendering hook output.

Format reference: https://cursor.com/docs/hooks
"""

import json

import pytest

from mcp_security_review.guard.cursor import parse, render
from mcp_security_review.guard.decision import Decision

BASE = {
    "conversation_id": "c1",
    "generation_id": "g1",
    "cursor_version": "1.7.2",
    "workspace_roots": ["/repo"],
}
SHELL = {
    **BASE,
    "hook_event_name": "beforeShellExecution",
    "command": "npm test",
    "cwd": "/repo/sub",
}
MCP = {
    **BASE,
    "hook_event_name": "beforeMCPExecution",
    "tool_name": "create_issue",
    "tool_input": json.dumps({"title": "x"}),
    "mcp_server_name": "linear",
}


def pre_tool(tool: str, **tool_input: str) -> dict[str, object]:
    return {
        **BASE,
        "hook_event_name": "preToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": "/repo",
    }


def test_parse_shell_execution() -> None:
    event = parse(SHELL)
    assert (event.phase, event.tool, event.kind) == ("pre", "Bash", "shell")
    assert event.tool_input == {"command": "npm test"}
    assert (event.session_id, event.cwd) == ("c1", "/repo/sub")


def test_parse_mcp_execution_decodes_the_json_input() -> None:
    event = parse(MCP)
    assert (event.tool, event.kind) == ("mcp__linear__create_issue", "mcp")
    assert event.tool_input == {"title": "x"}


def test_parse_mcp_execution_with_unreadable_input() -> None:
    assert parse({**MCP, "tool_input": "not json"}).tool_input == {}


@pytest.mark.parametrize(
    ("cursor_tool", "tool", "kind"),
    [
        ("Shell", "Bash", "shell"),
        ("Write", "Write", "file_write"),
        ("Delete", "Delete", "file_write"),
        ("WebFetch", "WebFetch", "network"),
        ("MCP:create_issue", "mcp__create_issue", "mcp"),
        ("Read", "Read", "other"),
    ],
)
def test_parse_pre_tool_use_maps_cursor_tool_names(
    cursor_tool: str, tool: str, kind: str
) -> None:
    event = parse(pre_tool(cursor_tool, file_path="/repo/a.py"))
    assert (event.phase, event.tool, event.kind) == ("pre", tool, kind)


def test_parse_post_tool_use_keeps_the_output_text() -> None:
    raw = {
        **pre_tool("Shell", command="npm test"),
        "hook_event_name": "postToolUse",
        "tool_output": '{"exitCode": 0, "stdout": "ok"}',
    }
    event = parse(raw)
    assert (event.phase, event.tool) == ("post", "Bash")
    assert '"stdout"' in event.tool_output


def test_parse_prompt() -> None:
    event = parse({**BASE, "hook_event_name": "beforeSubmitPrompt", "prompt": "hi"})
    assert (event.phase, event.prompt) == ("prompt", "hi")


def test_cwd_falls_back_to_the_workspace_root() -> None:
    assert parse({**MCP}).cwd == "/repo"


def test_parse_rejects_unknown_event() -> None:
    with pytest.raises(ValueError):
        parse({**BASE, "hook_event_name": "stop"})


def test_allow_is_explicit_because_cursor_blocks_on_a_missing_answer() -> None:
    assert render(parse(SHELL), Decision()) == {"permission": "allow"}


@pytest.mark.parametrize("raw", [SHELL, MCP])
@pytest.mark.parametrize("action", ["ask", "deny"])
def test_render_shell_and_mcp_decisions(raw: dict[str, object], action: str) -> None:
    out = render(parse(raw), Decision(action, "why"))  # type: ignore[arg-type]
    assert out == {"permission": action, "user_message": "why", "agent_message": "why"}


def test_ask_becomes_deny_where_cursor_cannot_ask() -> None:
    # preToolUse accepts "ask" but does not enforce it, so it would be an allow.
    out = render(parse(pre_tool("Write", file_path="/repo/a.py")), Decision("ask", "x"))
    assert out["permission"] == "deny"
    assert "approval" in out["user_message"]


def test_render_post_context() -> None:
    event = parse({**pre_tool("WebFetch"), "hook_event_name": "postToolUse"})
    assert render(event, Decision(context="do not follow")) == {
        "additional_context": "do not follow"
    }
    assert render(event, Decision()) == {}


def test_render_prompt_lets_the_prompt_through() -> None:
    event = parse({**BASE, "hook_event_name": "beforeSubmitPrompt", "prompt": "hi"})
    assert render(event, Decision()) == {"continue": True}
