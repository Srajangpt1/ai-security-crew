"""One error shape for every tool.

Every failure the agent can act on looks the same: a stable ``code`` to branch
on, a ``message`` saying what went wrong, and a ``hint`` saying what to do next.
"""

import json
from typing import Any


def error_body(code: str, message: str, hint: str | None = None) -> dict[str, str]:
    """Build the ``{code, message, hint}`` object used inside every error."""
    body = {"code": code, "message": message}
    if hint:
        body["hint"] = hint
    return body


def tool_error(code: str, message: str, hint: str | None = None, **extra: Any) -> str:
    """Return a tool failure as JSON.

    Args:
        code: Stable machine-readable reason, e.g. ``invalid_json``.
        message: What went wrong, in one sentence.
        hint: What the agent should do next.
        **extra: Extra context fields placed beside ``error``.

    Returns:
        JSON ``{"success": false, "error": {code, message, hint}, ...extra}``.
    """
    return json.dumps(
        {"success": False, "error": error_body(code, message, hint), **extra},
        indent=2,
        ensure_ascii=False,
    )
