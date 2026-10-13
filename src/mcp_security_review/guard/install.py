"""Write the guard's hooks into a Claude Code settings file."""

import json
from pathlib import Path
from typing import Any

# Matches both `asc-guard hook ...` and the uvx form.
MARKER = "asc-guard hook"
UVX_PREFIX = "uvx --from git+https://github.com/Srajangpt1/ai-security-crew asc-guard"
# (event, subcommand, matcher, timeout seconds)
EVENTS = (
    ("PreToolUse", "pre-tool-use", "*", 20),
    ("PostToolUse", "post-tool-use", "*", 20),
    ("UserPromptSubmit", "user-prompt", None, 10),
)


def build_hooks(prefix: str) -> dict[str, Any]:
    """The `hooks` block for the given command prefix."""
    hooks: dict[str, Any] = {}
    for event, sub, matcher, timeout in EVENTS:
        handler = {
            "type": "command",
            "command": f"{prefix} hook {sub}",
            "timeout": timeout,
        }
        group: dict[str, Any] = {"hooks": [handler]}
        if matcher:
            group["matcher"] = matcher
        hooks[event] = [group]
    return hooks


def _is_ours(group: dict[str, Any]) -> bool:
    return any(MARKER in str(h.get("command", "")) for h in group.get("hooks", []))


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
    """Add the hooks to a settings file. Returns True if the file changed."""
    try:
        current = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except ValueError as e:
        raise ValueError(f"{path} is not valid JSON: {e}") from e
    updated = merge_hooks(current, prefix)
    if updated == current:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
    return True
