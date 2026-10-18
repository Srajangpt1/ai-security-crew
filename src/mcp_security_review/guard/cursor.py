"""Cursor adapter: hook JSON in, hook JSON out.

Format reference: https://cursor.com/docs/hooks
"""

import json
from typing import Any

from mcp_security_review.guard.claude_code import _as_text
from mcp_security_review.guard.decision import Decision
from mcp_security_review.guard.events import Event, Phase

_PHASES: dict[str, Phase] = {
    "beforeShellExecution": "pre",
    "beforeMCPExecution": "pre",
    "preToolUse": "pre",
    "postToolUse": "post",
    "beforeSubmitPrompt": "prompt",
}
# Cursor tool names that differ from the ones the guard's rules use.
_TOOLS = {"Shell": "Bash"}
# Kinds whose Cursor hooks (beforeShell/MCPExecution) can ask the user.
_CAN_ASK = frozenset({"shell", "mcp"})


def _tool(name: str) -> str:
    if name.startswith("MCP:"):
        return "mcp__" + name.removeprefix("MCP:")
    return _TOOLS.get(name, name)


def _input(value: Any) -> dict[str, Any]:
    if isinstance(value, str):  # beforeMCPExecution sends the input as JSON text
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def parse(raw: dict[str, Any]) -> Event:
    """Turn Cursor's hook input into an Event.

    Raises:
        ValueError: If the event name is not one the guard handles.
    """
    name = str(raw.get("hook_event_name", ""))
    if name not in _PHASES:
        raise ValueError(f"unsupported hook event: {name!r}")
    roots = raw.get("workspace_roots")
    cwd = raw.get("cwd") or (roots[0] if isinstance(roots, list) and roots else "")
    if name == "beforeShellExecution":
        tool, tool_input = "Bash", {"command": str(raw.get("command", ""))}
    elif name == "beforeMCPExecution":
        server, mcp_tool = raw.get("mcp_server_name", ""), raw.get("tool_name", "")
        tool, tool_input = f"mcp__{server}__{mcp_tool}", _input(raw.get("tool_input"))
    else:
        tool = _tool(str(raw.get("tool_name", "")))
        tool_input = _input(raw.get("tool_input"))
    return Event(
        phase=_PHASES[name],
        session_id=str(raw.get("conversation_id", "")),
        cwd=str(cwd),
        tool=tool,
        tool_input=tool_input,
        tool_output=_as_text(raw.get("tool_output")),
        prompt=str(raw.get("prompt", "")),
    )


def render(event: Event, decision: Decision) -> dict[str, Any]:
    """Build the hook output. Always explicit: Cursor blocks the action when a
    permission hook's answer is invalid, so silence is not an option here.
    """
    if event.phase == "prompt":
        return {"continue": True}
    if event.phase == "post":
        return {"additional_context": decision.context} if decision.context else {}
    if decision.action == "allow":
        return {"permission": "allow"}
    action, reason = decision.action, decision.reason
    if action == "ask" and event.kind not in _CAN_ASK:
        # preToolUse accepts "ask" but runs the tool anyway, so refuse instead.
        action = "deny"
        reason += (
            " Cursor cannot ask for your approval of this tool, so asc-guard"
            " blocked it. Run it yourself if you want it."
        )
    return {"permission": action, "user_message": reason, "agent_message": reason}
