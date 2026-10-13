"""Deterministic rule: the agent may not edit agent config or hook files.

A prompt-injected agent could switch the guard off by rewriting its own
settings, so this one rule does not depend on the decision model.
"""

import os
import shlex
from fnmatch import fnmatch
from pathlib import Path

from mcp_security_review.guard.events import Event

# Matched against the end of the absolute path.
PROTECTED = (
    ".claude/settings*.json",
    ".claude.json",
    ".claude/hooks/*",
    ".claude/plugins/*",
    ".mcp.json",
    ".cursor/mcp.json",
    ".cursor/hooks.json",
    ".codex/config.toml",
    ".codeium/windsurf/mcp_config.json",
    ".ai-security-crew/*",
)
# Shell commands that only read their arguments.
READ_ONLY_COMMANDS = frozenset(
    {"cat", "ls", "head", "tail", "less", "more", "grep", "rg", "stat", "wc", "diff"}
)
_SEPARATORS = frozenset({";", "&&", "||", "|", "&"})
_FILE_ARGS = ("file_path", "notebook_path", "path")


def _is_protected(token: str, cwd: str) -> bool:
    path = Path(os.path.expanduser(token))
    if not path.is_absolute():
        path = Path(cwd or ".") / path
    normalized = os.path.normpath(str(path))
    return any(fnmatch(normalized, f"*/{pattern}") for pattern in PROTECTED)


def _shell_hits(command: str, cwd: str) -> str | None:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return None
    segment: list[str] = []
    for token in [*tokens, ";"]:
        if token not in _SEPARATORS:
            segment.append(token)
            continue
        if segment and segment[0] not in READ_ONLY_COMMANDS:
            for arg in segment[1:]:
                if _is_protected(arg.lstrip("<>"), cwd):
                    return arg
        segment = []
    return None


def protected_target(event: Event) -> str | None:
    """The protected path this call would change, or None."""
    if event.kind == "file_write":
        for key in _FILE_ARGS:
            target = event.tool_input.get(key)
            if isinstance(target, str) and _is_protected(target, event.cwd):
                return target
    if event.kind == "shell":
        command = event.tool_input.get("command")
        if isinstance(command, str):
            return _shell_hits(command, event.cwd)
    return None
