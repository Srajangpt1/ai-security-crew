#!/bin/bash
# Installs the UserPromptSubmit hook into Claude Code settings.
# Safe to run multiple times — re-running updates the symlink if the repo has moved.
#
# Usage:
#   bash setup_claude_hook.sh            # global: fires in every project (default)
#   bash setup_claude_hook.sh --project  # project-level: fires only inside this repo
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK_SCRIPT="$REPO_DIR/scripts/security_hook.sh"
HOOKS_DIR="$HOME/.claude/hooks"
SYMLINK="$HOOKS_DIR/security_hook.sh"

# Parse flag
MODE="global"
for arg in "$@"; do
  case "$arg" in
    --project) MODE="project" ;;
    --global)  MODE="global"  ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

if [ "$MODE" = "project" ]; then
  SETTINGS_FILE="$REPO_DIR/.claude/settings.json"
  # Project-level: use the repo-relative path directly — no symlink needed because
  # the settings file and the hook script move together when the repo moves.
  REGISTERED_PATH="$HOOK_SCRIPT"
else
  SETTINGS_FILE="$HOME/.claude/settings.json"
  # Global: use a stable symlink so settings.json survives the repo being moved.
  mkdir -p "$HOOKS_DIR"
  ln -sf "$HOOK_SCRIPT" "$SYMLINK"
  echo "✓ Symlink: $SYMLINK -> $HOOK_SCRIPT"
  REGISTERED_PATH="$SYMLINK"
fi

chmod +x "$HOOK_SCRIPT"
mkdir -p "$(dirname "$SETTINGS_FILE")"
[ -f "$SETTINGS_FILE" ] || echo '{}' > "$SETTINGS_FILE"

python3 - "$SETTINGS_FILE" "$REGISTERED_PATH" <<'PYEOF'
import json
import os
import sys
import tempfile

settings_path, hook_script = sys.argv[1], sys.argv[2]

with open(settings_path) as f:
    settings = json.load(f)

hook_entry = {"type": "command", "command": hook_script}
hook_block = {"hooks": [hook_entry]}

hooks = settings.setdefault("hooks", {})
ups_hooks = hooks.setdefault("UserPromptSubmit", [])

if not any(hook_script in str(h) for h in ups_hooks):
    ups_hooks.append(hook_block)

    settings_dir = os.path.dirname(os.path.abspath(settings_path))
    with tempfile.NamedTemporaryFile("w", dir=settings_dir, delete=False, suffix=".tmp") as tmp:
        json.dump(settings, tmp, indent=2)
        tmp_path = tmp.name
    os.replace(tmp_path, settings_path)

    with open(settings_path) as f:
        json.load(f)  # validate

    print(f"✓ Hook registered in {settings_path}")
else:
    print(f"✓ Hook already registered in {settings_path} — no changes made")
PYEOF

echo "✓ scripts/security_hook.sh is executable"
echo ""
echo "Restart Claude Code for the hook to take effect."
if [ "$MODE" = "global" ]; then
  echo "If you move the repo, re-run this script to update the symlink."
else
  echo "Note: .claude/settings.json is gitignored — each developer must run this script once after cloning."
fi
