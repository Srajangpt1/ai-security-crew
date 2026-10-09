"""Tests for the shared tool error shape."""

import json

from mcp_security_review.errors import error_body, tool_error


def test_tool_error_has_code_message_hint_and_extras() -> None:
    data = json.loads(tool_error("bad", "It broke.", "Try again.", file="a.md"))
    assert data == {
        "success": False,
        "error": {"code": "bad", "message": "It broke.", "hint": "Try again."},
        "file": "a.md",
    }


def test_hint_is_optional() -> None:
    assert error_body("bad", "It broke.") == {"code": "bad", "message": "It broke."}
