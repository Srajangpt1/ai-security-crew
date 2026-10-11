#!/usr/bin/env python3
"""Installs the UserPromptSubmit hook into Claude Code settings.

Safe to run multiple times — re-running updates the symlink if the repo has moved.

Usage:
    python3 scripts/setup_claude_hook.py            # global (default)
    python3 scripts/setup_claude_hook.py --project  # project-level only
"""

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path

REPO_DIR = Path(__file__).parent.parent
HOOK_SCRIPT = REPO_DIR / "scripts" / "security_hook.py"
_HOOKS_DIR = Path.home() / ".claude" / "hooks"
_SYMLINK = _HOOKS_DIR / "security_hook.py"


def _parse_mode() -> str:
    parser = argparse.ArgumentParser(description="Install Claude Code security hook")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--global",
        dest="mode",
        action="store_const",
        const="global",
        default="global",
    )
    group.add_argument(
        "--project",
        dest="mode",
        action="store_const",
        const="project",
    )
    return parser.parse_args().mode


def _make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _update_settings(settings_path: Path, hook_path: str) -> None:
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    if not settings_path.exists():
        settings_path.write_text("{}")

    settings = json.loads(settings_path.read_text())
    hook_entry = {"type": "command", "command": hook_path}
    hook_block = {"hooks": [hook_entry]}

    hooks = settings.setdefault("hooks", {})
    ups_hooks = hooks.setdefault("UserPromptSubmit", [])

    if not any(hook_path in str(h) for h in ups_hooks):
        ups_hooks.append(hook_block)

        with tempfile.NamedTemporaryFile(
            "w",
            dir=settings_path.parent,
            delete=False,
            suffix=".tmp",
        ) as tmp:
            json.dump(settings, tmp, indent=2)
            tmp_path = tmp.name
        os.replace(tmp_path, str(settings_path))

        json.loads(settings_path.read_text())  # validate
        print(f"✓ Hook registered in {settings_path}")
    else:
        print(f"✓ Hook already registered in {settings_path} — no changes made")


def main() -> None:
    mode = _parse_mode()

    if mode == "project":
        settings_file = REPO_DIR / ".claude" / "settings.json"
        registered_path = str(HOOK_SCRIPT)
    else:
        settings_file = Path.home() / ".claude" / "settings.json"
        _HOOKS_DIR.mkdir(parents=True, exist_ok=True)
        _SYMLINK.unlink(missing_ok=True)
        _SYMLINK.symlink_to(HOOK_SCRIPT)
        print(f"✓ Symlink: {_SYMLINK} -> {HOOK_SCRIPT}")
        registered_path = str(_SYMLINK)

    _make_executable(HOOK_SCRIPT)
    _update_settings(settings_file, registered_path)

    print("✓ scripts/security_hook.py is executable")
    print()
    print("Restart Claude Code for the hook to take effect.")
    if mode == "global":
        print("If you move the repo, re-run this script to update the symlink.")
    else:
        print(
            "Note: .claude/settings.json is gitignored"
            " — each developer must run this script once after cloning."
        )


if __name__ == "__main__":
    main()
