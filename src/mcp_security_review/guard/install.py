"""Write the guard's hooks into a Claude Code settings file."""

import json
import re
import shutil
from pathlib import Path
from typing import Any

# The guard's own hook commands, in every form the installer has written:
# `asc-guard hook`, a full path (`.../asc-guard.EXE hook`, quoted or not), uvx.
_OURS = re.compile(r"asc-guard(\.exe)?\"?\s+hook\b", re.IGNORECASE)
UVX_PREFIX = "uvx --from git+https://github.com/Srajangpt1/ai-security-crew asc-guard"
# Without a key the guard is off, so skip starting it at all: each start costs
# about a second, on every tool call.
GATE = '[ -n "$TYPESAFE_API_KEY$ASC_GUARD_ENABLE" ] || exit 0; '
# (event, subcommand, matcher, timeout seconds)
EVENTS = (
    ("PreToolUse", "pre-tool-use", "*", 20),
    ("PostToolUse", "post-tool-use", "*", 20),
    ("UserPromptSubmit", "user-prompt", None, 10),
)


def _command_word(path: str) -> str | None:
    """A path as one word that bash and cmd.exe both run, or None if unsafe."""
    word = path.replace("\\", "/")
    if any(c in word for c in '"$`%!'):  # a shell would expand or end these
        return None
    return f'"{word}"' if any(c.isspace() for c in word) else word


def hook_prefix() -> str:
    """How the hooks start the guard.

    A full path when asc-guard is installed for good, so apps that start with a
    short PATH (from the macOS Dock, for one) still find it. Under uvx the guard
    runs from a throwaway environment, so the hooks call uvx instead.
    """
    found = shutil.which("asc-guard")
    # shortcut: uvx keeps throwaway environments under `archive-v0` in uv's
    # cache; update the check if uv renames it.
    if found and "archive-v0" not in found.replace("\\", "/").split("/"):
        return _command_word(found) or "asc-guard"
    uvx = shutil.which("uvx")
    word = _command_word(uvx) if uvx else None
    return word + UVX_PREFIX.removeprefix("uvx") if word else UVX_PREFIX


def build_hooks(prefix: str) -> dict[str, Any]:
    """The `hooks` block for the given command prefix."""
    hooks: dict[str, Any] = {}
    for event, sub, matcher, timeout in EVENTS:
        handler = {
            "type": "command",
            "command": f"{GATE}{prefix} hook {sub}",
            "timeout": timeout,
        }
        group: dict[str, Any] = {"hooks": [handler]}
        if matcher:
            group["matcher"] = matcher
        hooks[event] = [group]
    return hooks


def is_guard_command(command: str) -> bool:
    """True for a hook command that runs the guard."""
    return bool(_OURS.search(command))


def _is_ours(group: dict[str, Any]) -> bool:
    return any(
        isinstance(h, dict) and is_guard_command(str(h.get("command", "")))
        for h in group.get("hooks", [])
    )


def _check(settings: Any, path: Path) -> None:
    """Refuse settings we would have to throw parts of away to merge into."""
    if not isinstance(settings, dict):
        raise ValueError(f"{path}: expected a JSON object at the top level")
    hooks = settings.get("hooks", {})
    shaped = isinstance(hooks, dict) and all(
        isinstance(entries, list) and all(isinstance(e, dict) for e in entries)
        for entries in hooks.values()
    )
    if not shaped:
        raise ValueError(f"{path}: 'hooks' must map each event to a list of objects")


def merge_hooks(settings: dict[str, Any], prefix: str) -> dict[str, Any]:
    """Return settings with our hooks added, replacing any earlier copy."""
    merged = dict(settings)
    existing: dict[str, list[dict[str, Any]]] = dict(merged.get("hooks", {}))
    for event, groups in build_hooks(prefix).items():
        kept = [g for g in existing.get(event, []) if not _is_ours(g)]
        existing[event] = [*kept, *groups]
    merged["hooks"] = existing
    return merged


def install(path: Path, prefix: str) -> bool:
    """Add the hooks to a settings file. Returns True if the file changed.

    Raises:
        ValueError: The file is not valid JSON or not in the expected shape.
        OSError: The file could not be read or written.

    On either error the file is left exactly as it was.
    """
    if path.is_symlink():
        path = path.resolve()  # update the file the link points to, keep the link
    try:
        # utf-8-sig: Windows editors often save JSON with a byte order mark.
        text = path.read_text(encoding="utf-8-sig") if path.exists() else "{}"
        current = json.loads(text)
    except ValueError as e:
        raise ValueError(f"{path} is not valid JSON: {e}") from e
    _check(current, path)
    updated = merge_hooks(current, prefix)
    if updated == current:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write a copy, then swap it in, so a failed write never truncates the file.
    tmp = path.with_name(f"{path.name}.asc-guard.tmp")
    try:
        tmp.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
        if path.exists():
            shutil.copymode(path, tmp)  # a private settings file stays private
        tmp.replace(path)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise
    return True
