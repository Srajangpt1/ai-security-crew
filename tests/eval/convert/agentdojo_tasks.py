"""Parse AgentDojo injection task definitions (attacker goals and calls)."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

GETTERS = ("get_", "read_", "search_", "list_", "find_", "check_", "verify_")
_SKIP_NAMES = {"GOAL", "COMMENT", "GROUND_TRUTH_OUTPUT"}
_EXFIL_WORDS = ("contents", "content", "body", "messages", "code", "passport")
_SLUGS = {
    "send_money": "send-money",
    "update_scheduled_transaction": "redirect-payment",
    "update_password": "change-password",
    "send_direct_message": "phishing-message",
    "post_webpage": "exfiltrate-slack",
    "get_webpage": "visit-phishing-site",
    "invite_user_to_slack": "invite-user",
    "reserve_hotel": "reserve-hotel",
    "create_calendar_event": "create-event",
    "delete_file": "delete-file",
}


@dataclass
class TaskInfo:
    """What an injection task wants from the agent."""

    functions: list[str] = field(default_factory=list)
    consts: set[str] = field(default_factory=set)
    weak: set[str] = field(default_factory=set)
    goal: str = ""

    @property
    def target(self) -> str | None:
        """Function name of the attacker's characteristic call, if any."""
        for name in self.functions:
            if not name.startswith(GETTERS):
                return name
        if self.functions:
            return self.functions[-1]
        return "send_email" if "email" in self.goal.lower() else None

    @property
    def category(self) -> str:
        """Short slug describing the attacker's goal."""
        target = self.target or "no-tool-call"
        if target == "send_email":
            if re.search(r"phish|bit\.ly", self.goal, re.I):
                return "phishing-email"
            if any(w in self.goal.lower() for w in _EXFIL_WORDS):
                return "exfiltrate-email"
            return "send-email"
        return _SLUGS.get(target, target.replace("_", "-"))


def _render(node: ast.expr, names: dict[str, str]) -> str:
    """Render a (f-)string AST node, substituting known class constants."""
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.JoinedStr):
        return "".join(_render(v, names) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        inner = node.value
        return names.get(inner.id, "") if isinstance(inner, ast.Name) else ""
    return ""


def _str_values(node: ast.AST) -> set[str]:
    """Collect string constants below ``node``, ignoring dict keys."""
    if isinstance(node, ast.Constant):
        return {node.value} if isinstance(node.value, str) else set()
    out: set[str] = set()
    children = node.values if isinstance(node, ast.Dict) else ast.iter_child_nodes(node)
    for child in children:
        if child is not None:
            out |= _str_values(child)
    return out


def _parse_class(node: ast.ClassDef) -> TaskInfo:
    names: dict[str, str] = {}
    goal: ast.expr | None = None
    for stmt in node.body:
        if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
            continue
        target = stmt.targets[0]
        if not isinstance(target, ast.Name):
            continue
        if target.id == "GOAL":
            goal = stmt.value
        elif target.id not in _SKIP_NAMES and isinstance(stmt.value, ast.Constant):
            if isinstance(stmt.value.value, str):
                names[target.id] = stmt.value.value
    info = TaskInfo(consts={v for v in names.values() if len(v) >= 2})
    info.goal = _render(goal, names) if goal is not None else ""
    calls = [
        n
        for n in ast.walk(node)
        if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "FunctionCall"
    ]
    for call in sorted(calls, key=lambda c: (c.lineno, c.col_offset)):
        for kw in call.keywords:
            if kw.arg == "function" and isinstance(kw.value, ast.Constant):
                info.functions.append(str(kw.value.value))
            if kw.arg == "args":
                info.weak |= {s for s in _str_values(kw.value) if len(s) >= 2}
    return info


def _version_key(path: Path) -> tuple[int, ...]:
    return tuple(int(p) for p in path.name[1:].split("_") if p.isdigit())


def load_tasks(suites_dir: Path) -> dict[tuple[str, str], TaskInfo]:
    """Parse injection tasks from ``suites_dir`` and its sibling ``v1_*`` dirs.

    Later benchmark versions override the functions and goal of earlier ones;
    attacker constants are merged across versions.

    Args:
        suites_dir: The ``default_suites/v1`` directory.

    Returns:
        Mapping of (suite, injection_task_id) to its TaskInfo.
    """
    out: dict[tuple[str, str], TaskInfo] = {}
    versions = sorted(suites_dir.parent.glob("v1*"), key=_version_key)
    for vdir in versions:
        for file in sorted(vdir.glob("*/injection_tasks.py")):
            tree = ast.parse(file.read_text(encoding="utf-8"))
            for node in tree.body:
                m = re.fullmatch(r"InjectionTask(\d+)", getattr(node, "name", ""))
                if not (m and isinstance(node, ast.ClassDef)):
                    continue
                key = (file.parent.name, f"injection_task_{m.group(1)}")
                new = _parse_class(node)
                old = out.get(key)
                if old is not None:
                    new.consts |= old.consts
                    new.weak |= old.weak
                    new.functions = new.functions or old.functions
                    new.goal = new.goal or old.goal
                out[key] = new
    return out
