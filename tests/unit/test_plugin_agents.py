"""Checks on the agent profiles and plugin manifests shipped for Claude Code and Cursor."""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
AGENTS = sorted((ROOT / "agents").glob("*.md"))
# Claude Code ignores these fields in plugin agents, so they must not be relied on.
IGNORED_IN_PLUGINS = {"permissionMode", "hooks", "mcpServers", "initialPrompt"}


def _frontmatter(path: Path) -> dict[str, Any]:
    text = path.read_text()
    assert text.startswith("---\n"), f"{path.name} has no frontmatter"
    data = yaml.safe_load(text.split("---\n", 2)[1])
    assert isinstance(data, dict)
    return data


def _manifest(folder: str, name: str) -> dict[str, Any]:
    data = json.loads((ROOT / folder / name).read_text())
    assert isinstance(data, dict)
    return data


def test_agents_are_shipped() -> None:
    assert {p.stem for p in AGENTS} == {
        "security-reviewer",
        "finding-verifier",
        "dependency-auditor",
        "threat-modeler",
    }


@pytest.mark.parametrize("path", AGENTS, ids=lambda p: p.stem)
def test_agent_frontmatter_works_in_both_clients(path: Path) -> None:
    meta = _frontmatter(path)
    assert meta["name"] == path.stem
    assert ":" not in meta["name"]
    assert len(meta["description"]) > 50
    assert meta["model"] == "inherit"
    assert not IGNORED_IN_PLUGINS & meta.keys()
    # Read-only in both clients: Cursor reads `readonly`, Claude Code the tool list.
    assert meta["readonly"] is True
    blocked = {t.strip() for t in meta["disallowedTools"].split(",")}
    assert {"Write", "Edit", "NotebookEdit"} <= blocked


def test_cursor_and_claude_plugins_match() -> None:
    claude = _manifest(".claude-plugin", "plugin.json")
    cursor = _manifest(".cursor-plugin", "plugin.json")
    assert cursor["name"] == claude["name"]
    assert cursor["mcpServers"] == claude["mcpServers"]


def test_cursor_plugin_does_not_load_claude_hooks() -> None:
    # hooks/hooks.json is in Claude Code's format. The inline value replaces
    # Cursor's default discovery of that file.
    cursor = _manifest(".cursor-plugin", "plugin.json")
    assert cursor["hooks"] == {"version": 1, "hooks": {}}


def test_cursor_marketplace_lists_the_plugin() -> None:
    market = _manifest(".cursor-plugin", "marketplace.json")
    assert [p["name"] for p in market["plugins"]] == ["mcp-security-review"]
