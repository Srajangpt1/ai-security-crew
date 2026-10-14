"""Read AgentDojo run files and locate injections and attacker calls."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tests.eval.convert.agentdojo_tasks import TaskInfo

OMIT = "\n[... omitted ...]\n"


@dataclass
class Hit:
    """An injection found inside a tool result."""

    index: int
    tool: str
    output: str
    injected: str
    placement: str


def clip(text: str, limit: int, head_frac: float) -> str:
    """Clip ``text`` to ``limit`` chars keeping both ends.

    Args:
        text: Text to clip.
        limit: Maximum length of the result, marker included.
        head_frac: Fraction of the kept characters taken from the start.

    Returns:
        The text unchanged if short enough, else start + marker + end.
    """
    if len(text) <= limit:
        return text
    keep = limit - len(OMIT)
    head = int(keep * head_frac)
    return text[:head] + OMIT + text[len(text) - (keep - head) :]


def load_run(path: Path) -> dict[str, Any] | None:
    """Load a run file; None if unreadable or lacking messages/security."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or "security" not in data:
        return None
    if not isinstance(data.get("messages"), list):
        return None
    return data


def text_of(content: Any) -> str | None:
    """Flatten message content (a string or a list of text parts) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [p.get("content") for p in content if isinstance(p, dict)]
        return "\n".join(p for p in parts if isinstance(p, str))
    return None


def first_user_message(run: dict[str, Any]) -> str | None:
    """Return the first user message text of a run."""
    for msg in run["messages"]:
        if msg.get("role") == "user" and text_of(msg.get("content")):
            return text_of(msg["content"])
    return None


def tool_name(msg: dict[str, Any]) -> str:
    """Function name of the call that produced a tool message."""
    return str((msg.get("tool_call") or {}).get("function", ""))


def _placement(content: str, m: re.Match[str]) -> str:
    """Where the match sits: start, middle or end, by position."""
    junk = " \t\r\n'\""
    if not content[: m.start()].strip(junk):
        return "start"
    if not content[m.end() :].strip(junk):
        return "end"
    center = (m.start() + m.end()) / 2 / len(content)
    return "start" if center < 1 / 3 else "end" if center > 2 / 3 else "middle"


def injection_pattern(text: str) -> re.Pattern[str]:
    """Regex matching ``text`` however punctuation and whitespace were mangled."""
    return re.compile(r"\W+".join(re.findall(r"\w+", text)))


def find_injection(run: dict[str, Any]) -> Hit | None:
    """Find the first tool result containing any injected text of the run."""
    texts = [t.strip() for t in run.get("injections", {}).values() if t.strip()]
    pats = [injection_pattern(t) for t in texts]
    for i, msg in enumerate(run["messages"]):
        content = text_of(msg.get("content"))
        if msg.get("role") != "tool" or not content:
            continue
        flat = content.replace("\\n", " ").replace("\\t", " ")  # repr'd output
        for text, pat in zip(texts, pats, strict=True):
            for variant in (content, flat):
                m = pat.search(variant)
                if m is not None:
                    place = _placement(variant, m)
                    return Hit(i, tool_name(msg), content, text, place)
    return None


def _score(args: dict[str, Any], info: TaskInfo) -> int:
    blob = json.dumps(args, sort_keys=True)
    strong = sum(c in blob for c in info.consts)
    weak = sum(c in blob for c in info.weak)
    if info.consts and not strong:
        return 0
    if not info.consts and info.weak and not weak:
        return 0
    return 3 * strong + weak + 1


def find_attacker_call(
    run: dict[str, Any], info: TaskInfo, after: int
) -> dict[str, Any] | None:
    """Pick the assistant tool call matching the injection task's goal.

    Args:
        run: Loaded run.
        info: Parsed injection task.
        after: Message index of the injected tool result; earlier calls are
            ignored.

    Returns:
        The best-scoring call ({"function", "args"}), earliest on ties, or None.
    """
    best: tuple[int, dict[str, Any]] | None = None
    for msg in run["messages"][after + 1 :]:
        for call in msg.get("tool_calls") or []:
            if call["function"] != info.target or not call.get("args"):
                continue
            score = _score(call["args"], info)
            if score and (best is None or score > best[0]):
                best = (score, call)
    return best[1] if best else None
