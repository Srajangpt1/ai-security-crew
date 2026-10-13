"""Append-only log of what the guard decided."""

import json
import time

from mcp_security_review.guard.decision import Decision
from mcp_security_review.guard.events import Event
from mcp_security_review.guard.session import guard_home


def record(event: Event, decision: Decision, note: str = "") -> None:
    """Add one line to audit.jsonl. Failure to write never stops the guard."""
    entry = {
        "ts": round(time.time()),
        "session": event.session_id,
        "phase": event.phase,
        "tool": event.tool,
        "action": decision.action,
        "reason": decision.reason,
        "note": note,
    }
    try:
        path = guard_home() / "audit.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        return
