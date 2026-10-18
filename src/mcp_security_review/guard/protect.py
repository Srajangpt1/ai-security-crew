"""Deterministic rule: the agent may not edit agent config or hook files.

A prompt-injected agent could switch the guard off by rewriting its own
settings, so this one rule does not depend on the decision model. Shell
commands are read roughly the way a shell would read them, to catch the usual
ways around a plain path check: redirects, `sh -c` and interpreter one-liners,
`cd`, globs and braces, PowerShell, and removing a whole config folder.

What it cannot see: a script file run by name, or a path built at run time.
Those are left to the decision model.
"""

import base64
import binascii
import glob
import os
import re
import shlex
import sys
from collections.abc import Iterable, Iterator
from fnmatch import fnmatchcase
from itertools import islice, takewhile
from typing import Any

from mcp_security_review.guard.events import Event

# Matched, ignoring case, against the end of the absolute path.
PROTECTED = (
    ".claude/settings*.json",
    ".claude.json",
    ".claude/hooks/*",
    ".claude/plugins/*",
    ".mcp.json",
    ".vscode/mcp.json",
    "claude/claude_desktop_config.json",
    ".cursor/mcp.json",
    ".cursor/hooks.json",
    ".cursor/hooks/*",
    ".codex/config.toml",
    ".codeium/windsurf/mcp_config.json",
    ".config/devin/mcp_config.json",
    ".ai-security-crew/*",
)
# Folders that hold those files: removing or replacing one has the same effect.
PROTECTED_DIRS = (
    ".claude",
    ".cursor",
    ".codex",
    ".codeium/windsurf",
    ".config/devin",
    ".ai-security-crew",
)
# Commands that only read their arguments (redirects are still checked).
READ_ONLY_COMMANDS = frozenset(
    {"cat", "ls", "head", "tail", "less", "more", "grep", "rg", "stat", "wc", "diff"}
    | {"cd", "pushd", "file", "tree"}
    | {"get-content", "gc", "type", "select-string", "sls", "get-childitem"}
    | {"gci", "dir", "get-item", "gi", "test-path", "resolve-path"}
)
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "busybox"})
POWERSHELLS = frozenset({"pwsh", "powershell"})
_WRAPPERS = SHELLS | POWERSHELLS | {"cmd", "eval"}
INTERPRETER = re.compile(r"(python[\d.]*|py|node|perl|ruby|php|deno|bun)")
# Argument names that hold a path in file and MCP tools.
PATH_KEY = re.compile(r"path|file|target|source|dest|dir|uri", re.IGNORECASE)
# MCP tools whose names say they only read.
READ_VERBS = ("read", "get", "list", "search", "find", "view", "show", "stat", "dir")
_OPERATOR = re.compile(r"[;&|()<>]+")
_SEPARATOR = re.compile(r"[;&|()]+")  # ends one command; `<` and `>` do not
_CHAIN = re.compile(r"[;&|]+")  # ends a command even inside interpreter code
_ASSIGNMENT = re.compile(r"[A-Za-z_]\w*=")
_WORD_BREAK = re.compile(r"[\s'\"(),;=`{}\[\]]+")
_BRACE = re.compile(r"\{([^{}]*,[^{}]*)\}")
# Longer commands are refused unread. Checking one this long takes about 3 s in
# the worst case; much longer could outlast the hook's timeout (20 s, shared
# with the Jev call), and the client lets a call through when its hook times out.
MAX_COMMAND = 300_000
_MAX_DEPTH = 4
_MAX_EXPANSIONS = 64
_MAX_DISK_CHECKS = 200


def _braces(token: str) -> list[str]:
    """Expand `{a,b}` the way bash would, up to a limit."""
    match = _BRACE.search(token)
    if not match:
        return [token]
    out: list[str] = []
    for part in match.group(1).split(","):
        out += _braces(token[: match.start()] + part + token[match.end() :])
    return out[:_MAX_EXPANSIONS]


def _absolute(token: str, cwd: str) -> str:
    """Absolute path with forward slashes; backslashes count as separators."""
    path = os.path.expanduser(token.removeprefix("file://").replace("\\", "/"))
    if not os.path.isabs(path):
        path = os.path.join((cwd or os.getcwd()).replace("\\", "/"), path)
    return os.path.normpath(path).replace("\\", "/")


def _matches(path: str) -> bool:
    folded = path.casefold()
    return any(fnmatchcase(folded, f"*/{p}") for p in PROTECTED) or any(
        folded.endswith(f"/{d}") for d in PROTECTED_DIRS
    )


def _named(token: str, cwd: str) -> bool:
    """The text itself names a protected path. No file system access."""
    for candidate in _braces(token):
        try:
            if _matches(_absolute(candidate, cwd)):
                return True
        except ValueError:  # e.g. a NUL byte in the path
            continue
    return False


def _on_disk(token: str, cwd: str) -> bool:
    """A symlink or glob that leads to a protected path on this machine."""
    for candidate in _braces(token):
        try:
            path = _absolute(candidate, cwd)
            if _matches(os.path.realpath(path).replace("\\", "/")):
                return True
            if any(c in candidate for c in "*?["):
                hidden = {"include_hidden": True} if sys.version_info >= (3, 11) else {}
                found = glob.iglob(path, **hidden)  # type: ignore[call-overload]
                if any(_matches(f.replace("\\", "/")) for f in islice(found, 200)):
                    return True
        except (OSError, ValueError):
            continue
    return False


class _Budget:
    """Disk checks left for one tool call.

    Text checks cover every token, but a disk check costs a system call, and a
    padded command must not run the hook past its timeout, which the client
    treats as "allow". shortcut: 200 per call; raise it if symlinked or globbed
    config paths beyond that turn up in practice.
    """

    def __init__(self) -> None:
        self.left = _MAX_DISK_CHECKS


def _first_protected(tokens: Iterable[str], cwd: str, budget: _Budget) -> str | None:
    """The first token that names or leads to a protected path."""
    # `--output=.mcp.json` and `F=.mcp.json` hold the path after the `=`.
    variants = (v for t in tokens for v in (t, t.partition("=")[2]))
    distinct = [t for t in dict.fromkeys(variants) if t and not _OPERATOR.fullmatch(t)]
    hit = next((t for t in distinct if _named(t, cwd)), None)
    for token in distinct if hit is None else ():
        if budget.left <= 0:
            break
        budget.left -= 1
        if _on_disk(token, cwd):
            return token
    return hit


def _tokens(command: str, *, escapes: bool) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    if not escapes:
        lexer.escape = ""  # keep backslashes: Windows paths, PowerShell
    try:
        return list(lexer)
    except ValueError:  # unbalanced quotes: a shell would refuse it too
        return command.split()


def _name(token: str) -> str:
    """Lower-case program name without folder or .exe."""
    base = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base.removesuffix(".exe")


def _decode_powershell(text: str) -> str:
    try:
        return base64.b64decode(text, validate=True).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ""


def _nested(segment: list[str]) -> Iterator[str]:
    """Commands that a segment hands to another shell as a string."""
    for i, token in enumerate(segment):
        name = _name(token)
        if name not in _WRAPPERS:
            continue
        rest = segment[i + 1 :]
        if name in SHELLS:
            for j, flag in enumerate(rest[:-1]):
                if flag.startswith("-") and not flag.startswith("--") and "c" in flag:
                    yield rest[j + 1]
                    break
        elif name in POWERSHELLS:
            for j, flag in enumerate(rest):
                lowered = flag.lower()
                if lowered.startswith("-e") and not lowered.startswith("-ex"):
                    yield _decode_powershell(rest[j + 1] if j + 1 < len(rest) else "")
                elif lowered.startswith("-c"):
                    yield " ".join(rest[j + 1 :])
        elif name == "cmd":
            for j, flag in enumerate(rest):
                if flag.lower() in ("/c", "/k"):
                    yield " ".join(rest[j + 1 :])
        elif name == "eval":
            yield " ".join(rest)
    # Command substitution, even inside quotes: `$(...)` and backticks.
    if any("$(" in t or "`" in t for t in segment):
        text = " ".join(segment)
        yield text.replace("$(", " ; ").replace(")", " ; ").replace("`", " ; ")


def _segment_hit(
    segment: list[str], cwd: str, depth: int, budget: _Budget
) -> str | None:
    command = _name(segment[0])
    redirect_targets = [
        segment[i + 1]
        for i, t in enumerate(segment[:-1])
        if ">" in t and _OPERATOR.fullmatch(t)
    ]
    if command in READ_ONLY_COMMANDS:
        candidates = redirect_targets
    else:  # a leading `F=path` assignment counts as an argument
        candidates = segment if _ASSIGNMENT.match(segment[0]) else segment[1:]
    hit = _first_protected(candidates, cwd, budget)
    if hit:
        return hit
    for inner in _nested(segment):
        hit = _shell_hit(inner, cwd, budget, depth + 1)
        if hit:
            return hit
    return None


def _interpreter_hit(tokens: list[str], cwd: str, budget: _Budget) -> str | None:
    """Config paths in code passed to an interpreter inline or as a heredoc.

    The code runs until the next command separator; parentheses inside it are
    the code's own, so they do not end it.
    """
    for i, token in enumerate(tokens):
        if not INTERPRETER.fullmatch(_name(token)):
            continue
        code = takewhile(lambda t: not _CHAIN.fullmatch(t), tokens[i + 1 :])
        words = (w for t in code for w in _WORD_BREAK.split(t))
        hit = _first_protected(words, cwd, budget)
        if hit:
            return hit
    return None


def _shell_hit(command: str, cwd: str, budget: _Budget, depth: int = 0) -> str | None:
    if not command.strip():
        return None
    if depth > _MAX_DEPTH:
        # Nested deeper than the parser follows: any config path in it counts.
        return _first_protected(_WORD_BREAK.split(command), cwd, budget)
    # Bash reads `\` as an escape, Windows as a separator: check both readings.
    for escapes in (True, False):
        tokens = _tokens(command, escapes=escapes)
        hit = _interpreter_hit(tokens, cwd, budget)
        if hit:
            return hit
        here, segment = cwd, []
        for token in [*tokens, ";"]:
            if not _SEPARATOR.fullmatch(token):
                segment.append(token)
                continue
            if segment:
                hit = _segment_hit(segment, here, depth, budget)
                if hit:
                    return hit
                if _name(segment[0]) in ("cd", "pushd") and len(segment) > 1:
                    here = _absolute(segment[1], here)
            segment = []
    return None


def _path_values(tool_input: dict[str, Any]) -> Iterator[str]:
    for key, value in tool_input.items():
        if not PATH_KEY.search(str(key)):
            continue
        values = value if isinstance(value, list) else [value]
        yield from (v for v in values if isinstance(v, str))


def block_reason(event: Event) -> str | None:
    """Why this call must not run, or None if the rule has no objection."""
    command = event.tool_input.get("command") if event.kind == "shell" else None
    if isinstance(command, str) and len(command) > MAX_COMMAND:
        return (
            "Blocked: this command is too long for the guard to check. "
            "Ask the user to run it themselves."
        )
    target = protected_target(event)
    if target:
        return (
            f"Blocked: {target} is agent config or a hook file. "
            "Ask the user to change it themselves."
        )
    return None


def protected_target(event: Event) -> str | None:
    """The protected path this call would change, or None."""
    budget = _Budget()
    mcp_write = event.kind == "mcp" and not _name(
        event.tool.rsplit("__", 1)[-1]
    ).startswith(READ_VERBS)
    if event.kind == "file_write" or mcp_write:
        hit = _first_protected(_path_values(event.tool_input), event.cwd, budget)
        if hit:
            return hit
    if event.kind == "shell":
        command = event.tool_input.get("command")
        if isinstance(command, str):
            return _shell_hit(command, event.cwd, budget)
    return None
