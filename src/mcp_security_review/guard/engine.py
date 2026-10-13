"""Decide what to do with one event. Pure of any client format."""

import os
from typing import Any

from mcp_security_review.guard import audit
from mcp_security_review.guard.clip import clip
from mcp_security_review.guard.decision import Decision
from mcp_security_review.guard.events import READ_ONLY_TOOLS, Event
from mcp_security_review.guard.jev import JevClient, JevError
from mcp_security_review.guard.policy import (
    Thresholds,
    decide_action,
    load_questions,
    load_thresholds,
)
from mcp_security_review.guard.protect import protected_target
from mcp_security_review.guard.scan import WARNING, scan_result
from mcp_security_review.guard.session import SessionStore

# If Jev is down, these kinds of calls ask the user; the rest go ahead.
FAIL_ASK_KINDS = frozenset({"shell", "network", "mcp"})
MAX_FIELD = 2000


def is_enabled() -> bool:
    """The guard runs only when a key is set or ASC_GUARD_ENABLE is truthy."""
    flag = os.environ.get("ASC_GUARD_ENABLE", "").lower()
    return bool(os.environ.get("TYPESAFE_API_KEY")) or flag in ("1", "true", "yes")


def _trim(value: Any) -> Any:
    if isinstance(value, str):
        return clip(value, MAX_FIELD)
    if isinstance(value, dict):
        return {k: _trim(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_trim(v) for v in value[:20]]
    return value


def _pre(
    event: Event, client: JevClient, store: SessionStore, t: Thresholds
) -> Decision:
    target = protected_target(event)
    if target:
        return Decision(
            "deny",
            f"Blocked: {target} is agent config or a hook file. Ask the user to "
            "change it themselves.",
        )
    if event.tool in READ_ONLY_TOOLS:
        return Decision()
    state: dict[str, Any] = {
        "tool": event.tool,
        "input": _trim(event.tool_input),
        "cwd": event.cwd,
        "user_recent_messages": store.prompts(),
    }
    if store.flagged():
        state["flagged_untrusted_content"] = store.flagged()
    try:
        answers = client.ask(state, load_questions()["action"])
    except JevError as e:
        if event.kind in FAIL_ASK_KINDS:
            return Decision("ask", f"Security check unavailable ({e}); please confirm.")
        return Decision()
    return decide_action(answers, t)


def _post(
    event: Event, client: JevClient, store: SessionStore, t: Thresholds
) -> Decision:
    task = (store.prompts() or [""])[-1]
    try:
        flagged = scan_result(event, client, t, task)
    except JevError:
        return Decision()
    if not flagged:
        return Decision()
    store.add_flagged(event.tool_output)
    return Decision(context=WARNING.format(tool=event.tool))


def handle(
    event: Event,
    client: JevClient | None = None,
    store: SessionStore | None = None,
    thresholds: Thresholds | None = None,
) -> Decision:
    """Run the guard on one event and log the outcome."""
    client = client or JevClient()
    store = store or SessionStore(event.session_id)
    t = thresholds or load_thresholds()
    if event.phase == "prompt":
        store.add_prompt(event.prompt)
        return Decision()
    decision = (_pre if event.phase == "pre" else _post)(event, client, store, t)
    if decision.action != "allow" or decision.context:
        audit.record(event, decision)
    return decision
