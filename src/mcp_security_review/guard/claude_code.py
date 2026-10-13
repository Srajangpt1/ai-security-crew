"""Claude Code adapter: hook JSON in, hook JSON out.

Format reference: https://code.claude.com/docs/en/hooks
"""

import json
from typing import Any

from mcp_security_review.guard.decision import Decision
from mcp_security_review.guard.events import Event, Phase

_PHASES: dict[str, Phase] = {
    "PreToolUse": "pre",
    "PostToolUse": "post",
    "UserPromptSubmit": "prompt",
}


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False)


def parse(raw: dict[str, Any]) -> Event:
    """Turn Claude Code's hook input into an Event.

    Raises:
        ValueError: If the event name is not one the guard handles.
    """
    name = str(raw.get("hook_event_name", ""))
    if name not in _PHASES:
        raise ValueError(f"unsupported hook event: {name!r}")
    tool_input = raw.get("tool_input")
    return Event(
        phase=_PHASES[name],
        session_id=str(raw.get("session_id", "")),
        cwd=str(raw.get("cwd", "")),
        tool=str(raw.get("tool_name", "")),
        tool_input=tool_input if isinstance(tool_input, dict) else {},
        tool_output=_as_text(raw.get("tool_response")),
        prompt=str(raw.get("prompt", "")),
    )


def render(event: Event, decision: Decision) -> dict[str, Any] | None:
    """Build the hook output, or None to say nothing.

    An "allow" prints nothing on purpose: answering allow would skip Claude
    Code's own permission prompt, and the guard only adds caution.
    """
    if event.phase == "pre" and decision.action in ("ask", "deny"):
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision.action,
                "permissionDecisionReason": decision.reason,
            }
        }
    if event.phase == "post" and decision.context:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": decision.context,
            }
        }
    return None
