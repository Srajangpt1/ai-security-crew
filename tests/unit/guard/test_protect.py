"""The deterministic rule that protects agent config and hook files."""

import pytest

from mcp_security_review.guard.events import Event
from mcp_security_review.guard.protect import protected_target


def shell(command: str) -> Event:
    return Event("pre", "s", "/repo", "Bash", {"command": command})


def write(path: str, tool: str = "Write") -> Event:
    return Event("pre", "s", "/repo", tool, {"file_path": path})


@pytest.mark.parametrize(
    "path",
    [
        "/repo/.mcp.json",
        ".mcp.json",
        "/repo/.claude/settings.local.json",
        "~/.claude/settings.json",
        "~/.claude.json",
        "/repo/.cursor/hooks.json",
        "/repo/sub/../.claude/settings.json",
    ],
)
def test_file_tools_cannot_write_protected_files(path: str) -> None:
    assert protected_target(write(path)) is not None
    assert protected_target(write(path, "Edit")) is not None


@pytest.mark.parametrize("path", ["/repo/src/app.py", "/repo/.claude/commands/x.md"])
def test_other_files_are_fine(path: str) -> None:
    assert protected_target(write(path)) is None


@pytest.mark.parametrize(
    "command",
    [
        "echo '{}' > ~/.claude/settings.json",
        "sed -i s/a/b/ .mcp.json",
        "cat ok.txt && tee .claude/settings.json",
        "cp evil.json .cursor/mcp.json",
    ],
)
def test_shell_writes_to_protected_files_are_found(command: str) -> None:
    assert protected_target(shell(command)) is not None


@pytest.mark.parametrize(
    "command",
    [
        "cat .mcp.json",
        "grep hooks ~/.claude/settings.json | head",
        "npm test",
        "ls -la",
    ],
)
def test_shell_reads_are_fine(command: str) -> None:
    assert protected_target(shell(command)) is None


def test_unbalanced_quotes_do_not_crash() -> None:
    assert protected_target(shell("echo 'oops")) is None


def test_read_only_tools_are_ignored() -> None:
    event = Event("pre", "s", "/repo", "Read", {"file_path": "/repo/.mcp.json"})
    assert protected_target(event) is None
