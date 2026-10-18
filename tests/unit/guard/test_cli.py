"""The asc-guard command."""

import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from mcp_security_review.guard.cli import main
from mcp_security_review.guard.install import (
    GATE,
    UVX_PREFIX,
    build_hooks,
    hook_prefix,
    install,
    is_guard_command,
)

PRE = {
    "hook_event_name": "PreToolUse",
    "session_id": "s1",
    "cwd": "/repo",
    "tool_name": "Write",
    "tool_input": {"file_path": "/repo/.mcp.json", "content": "{}"},
}


def run(*args: str, stdin: str = "") -> tuple[int, str]:
    result = CliRunner().invoke(main, list(args), input=stdin)
    return result.exit_code, result.output


def test_hook_is_a_silent_no_op_when_not_enabled() -> None:
    assert run("hook", "pre-tool-use", stdin=json.dumps(PRE)) == (0, "")


def test_hook_denies_a_protected_edit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASC_GUARD_ENABLE", "1")
    code, out = run("hook", "pre-tool-use", stdin=json.dumps(PRE))
    body = json.loads(out)["hookSpecificOutput"]
    assert code == 0 and body["permissionDecision"] == "deny"


def test_hook_fails_open_on_bad_input(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASC_GUARD_ENABLE", "1")
    code, out = run("hook", "pre-tool-use", stdin="not json")
    assert code == 0 and "skipped" in out


def test_check_exit_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASC_GUARD_ENABLE", "1")
    code, out = run("check", "Write", json.dumps(PRE["tool_input"]), "--cwd", "/repo")
    assert code == 2 and json.loads(out)["action"] == "deny"
    assert run("check", "Read", '{"file_path": "/repo/a.py"}')[0] == 0


def test_install_print_does_not_touch_files(tmp_path: Path) -> None:
    code, out = run("install", "--print")
    assert code == 0 and "asc-guard" in out and "PreToolUse" in out


def test_install_is_idempotent_and_keeps_other_settings(tmp_path: Path) -> None:
    path = tmp_path / ".claude" / "settings.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"model": "x", "hooks": {"Stop": [{"hooks": []}]}}))
    assert install(path, "asc-guard") is True
    assert install(path, "asc-guard") is False
    data = json.loads(path.read_text())
    assert data["model"] == "x" and "Stop" in data["hooks"]
    assert len(data["hooks"]["PreToolUse"]) == 1


def test_install_replaces_an_older_copy(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    install(path, "old-prefix asc-guard")
    install(path, "asc-guard")
    commands = [
        g["hooks"][0]["command"]
        for g in json.loads(path.read_text())["hooks"]["PreToolUse"]
    ]
    assert commands == [GATE + "asc-guard hook pre-tool-use"]


def test_install_rejects_broken_json(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text("{oops")
    with pytest.raises(ValueError):
        install(path, "asc-guard")


def test_plugin_hooks_file_matches_the_installer() -> None:
    plugin = Path(__file__).parents[3] / "hooks" / "hooks.json"
    assert json.loads(plugin.read_text()) == {"hooks": build_hooks(UVX_PREFIX)}


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
@pytest.mark.parametrize(
    ("env", "code"),
    [
        ({}, 0),
        ({"TYPESAFE_API_KEY": "k"}, 1),
        ({"ASC_GUARD_ENABLE": "1"}, 1),
        # The key the plugin asks for when it is enabled.
        ({"CLAUDE_PLUGIN_OPTION_TYPESAFE_API_KEY": "k"}, 1),
    ],
)
def test_hook_command_skips_the_guard_without_a_key(
    env: dict[str, str], code: int
) -> None:
    # `false` stands in for the guard: it runs (exit 1) only when a key is set.
    command = build_hooks("false")["PreToolUse"][0]["hooks"][0]["command"]
    done = subprocess.run(
        ["sh", "-c", command], env={"PATH": os.environ["PATH"], **env}, check=False
    )
    assert done.returncode == code


# --- install --client: Claude Code and Cursor ---------------------------------

CLIENTS = ("claude-code", "cursor")
CONFIG = {
    "claude-code": Path(".claude") / "settings.json",
    "cursor": Path(".cursor") / "hooks.json",
}
# Event name in each client's config -> the `asc-guard hook` subcommand.
EXPECTED = {
    "claude-code": {
        "PreToolUse": "pre-tool-use",
        "PostToolUse": "post-tool-use",
        "UserPromptSubmit": "user-prompt",
    },
    "cursor": {
        "beforeShellExecution": "pre-tool-use",
        "beforeMCPExecution": "pre-tool-use",
        "preToolUse": "pre-tool-use",
        "postToolUse": "post-tool-use",
        "beforeSubmitPrompt": "user-prompt",
    },
}
PRE_EVENT = {"claude-code": "PreToolUse", "cursor": "preToolUse"}
# Someone's own hooks, already in the file before the guard is installed.
EXISTING: dict[str, dict[str, Any]] = {
    "claude-code": {
        "model": "x",
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "./a"}]}
            ],
            "Stop": [{"hooks": [{"type": "command", "command": "./b"}]}],
        },
    },
    "cursor": {
        "version": 1,
        "extra": True,
        "hooks": {
            "preToolUse": [{"command": "./a", "matcher": "Shell"}],
            "afterFileEdit": [{"command": "./b"}],
        },
    },
}
CURSOR_BASE = {
    "conversation_id": "c1",
    "cursor_version": "1.7.2",
    "workspace_roots": ["/repo"],
}
PROTECTED_EDIT = {
    "claude-code": PRE,
    "cursor": {
        **CURSOR_BASE,
        "hook_event_name": "preToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "/repo/.mcp.json", "content": "{}"},
        "cwd": "/repo",
    },
}


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.chdir(root)
    return root


def guard_commands(path: Path, client: str) -> dict[str, list[str]]:
    """Event -> the guard's commands in an installed config file."""
    hooks = json.loads(path.read_text(encoding="utf-8"))["hooks"]
    found: dict[str, list[str]] = {}
    for event, entries in hooks.items():
        handlers = (
            entries if client == "cursor" else [h for g in entries for h in g["hooks"]]
        )
        cmds = [h["command"] for h in handlers if is_guard_command(h["command"])]
        if cmds:
            found[event] = cmds
    return found


def hook_args(command: str) -> list[str]:
    """The arguments after `asc-guard` in an installed hook command."""
    words = shlex.split(command.split("; ")[-1])
    return words[words.index("hook") :]


@pytest.mark.parametrize("client", CLIENTS)
def test_install_registers_the_clients_hooks(project: Path, client: str) -> None:
    code, out = run("install", "--client", client)
    assert code == 0, out
    commands = guard_commands(project / CONFIG[client], client)
    assert set(commands) == set(EXPECTED[client])
    for event, sub in EXPECTED[client].items():
        assert len(commands[event]) == 1
        assert hook_args(commands[event][0])[-1] == sub


def test_install_without_client_still_means_claude_code(project: Path) -> None:
    assert run("install")[0] == 0
    assert (project / CONFIG["claude-code"]).exists()
    assert not (project / CONFIG["cursor"]).exists()


def test_cursor_config_uses_cursors_own_format(project: Path) -> None:
    run("install", "--client", "cursor")
    data = json.loads((project / CONFIG["cursor"]).read_text())
    assert data["version"] == 1
    for entries in data["hooks"].values():
        for entry in entries:
            assert "hooks" not in entry  # flat entries, unlike Claude Code
            assert hook_args(entry["command"])[:3] == ["hook", "--client", "cursor"]
            assert entry["timeout"] > 0


def test_cursor_commands_need_no_posix_shell(project: Path) -> None:
    run("install", "--client", "cursor")
    for commands in guard_commands(project / CONFIG["cursor"], "cursor").values():
        assert not commands[0].startswith("[")


def test_cursor_pre_tool_use_leaves_shell_and_mcp_to_their_own_hooks(
    project: Path,
) -> None:
    run("install", "--client", "cursor")
    data = json.loads((project / CONFIG["cursor"]).read_text())
    matcher = data["hooks"]["preToolUse"][0]["matcher"]
    for tool in ("Write", "Delete", "WebFetch", "WebSearch"):
        assert re.search(matcher, tool), tool
    for tool in ("Shell", "MCP:WriteFile", "Read", "Grep"):
        assert not re.search(matcher, tool), tool


def test_install_print_shows_the_cursor_format(project: Path) -> None:
    code, out = run("install", "--client", "cursor", "--print")
    assert code == 0
    data = json.loads(out)
    assert data["version"] == 1 and "beforeShellExecution" in data["hooks"]
    assert not any(project.iterdir())


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--client", "vscode"], "cursor"),  # lists the valid choices
        (["--client"], "requires an argument"),
    ],
)
def test_install_rejects_a_bad_client(
    project: Path, args: list[str], message: str
) -> None:
    code, out = run("install", *args)
    assert code == 2 and message in out
    assert not any(project.iterdir())


@pytest.mark.parametrize("client", CLIENTS)
def test_install_twice_adds_nothing(project: Path, client: str) -> None:
    run("install", "--client", client)
    first = (project / CONFIG[client]).read_text()
    code, out = run("install", "--client", client)
    assert code == 0 and "Already up to date" in out
    assert (project / CONFIG[client]).read_text() == first


@pytest.mark.parametrize("client", CLIENTS)
def test_install_keeps_existing_config(project: Path, client: str) -> None:
    path = project / CONFIG[client]
    path.parent.mkdir()
    path.write_text(json.dumps(EXISTING[client]))
    assert run("install", "--client", client)[0] == 0
    data = json.loads(path.read_text())
    for key, value in EXISTING[client].items():
        if key != "hooks":
            assert data[key] == value
    for event, entries in EXISTING[client]["hooks"].items():
        assert data["hooks"][event][: len(entries)] == entries  # ours go after


@pytest.mark.parametrize("client", CLIENTS)
def test_user_scope_creates_missing_folders_under_home(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, client: str
) -> None:
    home = tmp_path / "home"  # does not exist yet
    monkeypatch.setattr(Path, "home", lambda: home)
    assert run("install", "--client", client, "--scope", "user")[0] == 0
    assert set(guard_commands(home / CONFIG[client], client)) == set(EXPECTED[client])
    assert not any(project.iterdir())


@pytest.mark.parametrize(
    ("client", "text"),
    [
        *[(c, "{oops") for c in CLIENTS],
        *[(c, "[]") for c in CLIENTS],
        *[(c, '{"hooks": []}') for c in CLIENTS],
        ("claude-code", '{"hooks": {"PreToolUse": {}}}'),
        ("cursor", '{"version": 1, "hooks": {"preToolUse": {}}}'),
    ],
)
def test_install_refuses_a_malformed_config_and_leaves_it_alone(
    project: Path, client: str, text: str
) -> None:
    path = project / CONFIG[client]
    path.parent.mkdir()
    path.write_text(text)
    code, out = run("install", "--client", client)
    assert code == 1 and path.name in out
    assert path.read_text() == text


@pytest.mark.parametrize("client", CLIENTS)
def test_a_failed_write_keeps_the_old_config(
    project: Path, monkeypatch: pytest.MonkeyPatch, client: str
) -> None:
    path = project / CONFIG[client]
    path.parent.mkdir()
    original = json.dumps(EXISTING[client])
    path.write_text(original)
    real_write = Path.write_text

    def write_half_then_fail(self: Path, data: str, *a: Any, **k: Any) -> int:
        real_write(self, data[:10], *a, **k)
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_text", write_half_then_fail)
    result = CliRunner().invoke(main, ["install", "--client", client])
    monkeypatch.undo()
    assert result.exit_code == 1 and "disk full" in result.output
    assert isinstance(result.exception, SystemExit)  # an error message, no traceback
    assert path.read_text() == original
    assert [p.name for p in path.parent.iterdir()] == [path.name]


@pytest.mark.parametrize("client", CLIENTS)
def test_an_unwritable_location_is_a_clean_error(project: Path, client: str) -> None:
    (project / CONFIG[client].parent).write_text("a file where the folder goes")
    result = CliRunner().invoke(main, ["install", "--client", client])
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)


# --- the installed hooks run the guard ----------------------------------------


@pytest.mark.parametrize("client", CLIENTS)
def test_the_installed_hook_runs_the_guard(
    project: Path, monkeypatch: pytest.MonkeyPatch, client: str
) -> None:
    monkeypatch.setenv("ASC_GUARD_ENABLE", "1")
    run("install", "--client", client)
    command = guard_commands(project / CONFIG[client], client)[PRE_EVENT[client]][0]
    code, out = run(*hook_args(command), stdin=json.dumps(PROTECTED_EDIT[client]))
    assert code == 0
    body = json.loads(out)
    decision = (
        body["permission"]
        if client == "cursor"
        else body["hookSpecificOutput"]["permissionDecision"]
    )
    assert decision == "deny"


def test_installed_cursor_shell_hook_blocks_editing_its_own_config(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASC_GUARD_ENABLE", "1")
    run("install", "--client", "cursor")
    shell = guard_commands(project / CONFIG["cursor"], "cursor")
    payload = {
        **CURSOR_BASE,
        "hook_event_name": "beforeShellExecution",
        "command": "rm .cursor/hooks.json",
        "cwd": "/repo",
    }
    code, out = run(
        *hook_args(shell["beforeShellExecution"][0]), stdin=json.dumps(payload)
    )
    assert code == 0 and json.loads(out)["permission"] == "deny"


# --- `asc-guard hook --client cursor` ------------------------------------------


def test_cursor_hook_answers_allow_when_the_guard_is_off() -> None:
    # The guard is off here; the answer must still be valid JSON for Cursor.
    stdin = json.dumps(PROTECTED_EDIT["cursor"])
    code, out = run("hook", "--client", "cursor", "pre-tool-use", stdin=stdin)
    assert code == 0 and json.loads(out) == {"permission": "allow"}


def test_cursor_hook_fails_open_on_bad_input(monkeypatch: pytest.MonkeyPatch) -> None:
    # Any exit code other than 0 and 2 makes Cursor log the failure and allow.
    monkeypatch.setenv("ASC_GUARD_ENABLE", "1")
    code, out = run("hook", "--client", "cursor", "pre-tool-use", stdin="not json")
    assert code == 1 and "skipped" in out


def test_hook_rejects_an_unknown_client() -> None:
    code, out = run("hook", "--client", "vscode", "pre-tool-use")
    assert code == 2 and "cursor" in out  # lists the valid choices


def test_claude_code_hooks_leave_cursor_calls_to_the_cursor_hooks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Cursor also runs Claude Code's hooks; judging there too would double up.
    monkeypatch.setenv("ASC_GUARD_ENABLE", "1")
    stdin = json.dumps({**PRE, "cursor_version": "1.7.2"})
    assert run("hook", "pre-tool-use", stdin=stdin) == (0, "")


# --- reliability of the hook process -------------------------------------------


def test_hook_reads_stdin_as_utf8_whatever_the_locale(guard_home: Path) -> None:
    # Clients send UTF-8; Windows and C-locale shells default stdin to another code
    # page, which garbles the prompts the guard judges.
    env = {k: v for k, v in os.environ.items() if k != "PYTHONIOENCODING"}
    env.update(
        ASC_GUARD_ENABLE="1", PYTHONUTF8="0", PYTHONCOERCECLOCALE="0", LC_ALL="C"
    )
    prompt = "fix café → 测试"
    payload = {
        "hook_event_name": "UserPromptSubmit",
        "session_id": "u8",
        "prompt": prompt,
    }
    code = "from mcp_security_review.guard.cli import main; main()"
    subprocess.run(
        [sys.executable, "-c", code, "hook", "user-prompt"],
        input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        env=env,
        check=True,
    )
    stored = json.loads((guard_home / "sessions" / "u8.json").read_text("utf-8"))
    assert stored["prompts"] == [prompt]


@pytest.mark.parametrize(("client", "code"), [("claude-code", 0), ("cursor", 1)])
def test_an_unexpected_error_fails_open(
    monkeypatch: pytest.MonkeyPatch, client: str, code: int
) -> None:
    def broken(event: object) -> None:
        raise KeyError("surprise")

    monkeypatch.setenv("ASC_GUARD_ENABLE", "1")
    monkeypatch.setattr("mcp_security_review.guard.engine.handle", broken)
    payload = PRE if client == "claude-code" else PROTECTED_EDIT["cursor"]
    result = CliRunner().invoke(
        main, ["hook", "--client", client, "pre-tool-use"], input=json.dumps(payload)
    )
    assert result.exit_code == code and "skipped" in result.output
    assert not isinstance(result.exception, KeyError)


# --- installer edge cases -------------------------------------------------------


@pytest.mark.parametrize("client", CLIENTS)
def test_install_accepts_a_file_saved_with_a_bom(project: Path, client: str) -> None:
    path = project / CONFIG[client]
    path.parent.mkdir()
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(EXISTING[client]).encode())
    assert run("install", "--client", client)[0] == 0
    assert json.loads(path.read_text("utf-8"))["hooks"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
@pytest.mark.parametrize("client", CLIENTS)
def test_install_keeps_the_file_private(project: Path, client: str) -> None:
    path = project / CONFIG[client]
    path.parent.mkdir()
    path.write_text("{}")
    path.chmod(0o600)
    run("install", "--client", client)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("client", CLIENTS)
def test_install_writes_through_a_symlink(project: Path, client: str) -> None:
    real = project / "dotfiles" / "config.json"
    real.parent.mkdir()
    real.write_text("{}")
    link = project / CONFIG[client]
    link.parent.mkdir()
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("this system does not allow symlinks")
    assert run("install", "--client", client)[0] == 0
    assert link.is_symlink() and json.loads(real.read_text())["hooks"]


@pytest.mark.parametrize(
    ("found", "expected"),
    [
        # A stable install is called by its full path, so GUI apps with a short
        # PATH still find it.
        ({"asc-guard": "/home/u/.local/bin/asc-guard"}, "/home/u/.local/bin/asc-guard"),
        (
            {"asc-guard": r"C:\Users\me\.local\bin\asc-guard.EXE"},
            "C:/Users/me/.local/bin/asc-guard.EXE",
        ),
        (
            {"asc-guard": "/home/u/my projects/.venv/bin/asc-guard"},
            '"/home/u/my projects/.venv/bin/asc-guard"',
        ),
        # uvx runs from a throwaway environment that may be gone tomorrow.
        (
            {
                "asc-guard": "/home/u/.cache/uv/archive-v0/abc/bin/asc-guard",
                "uvx": "/home/u/.local/bin/uvx",
            },
            "/home/u/.local/bin/uvx" + UVX_PREFIX.removeprefix("uvx"),
        ),
        ({}, UVX_PREFIX),
        # A path a shell would read differently falls back to the plain name.
        ({"asc-guard": '/home/u/$weird"/asc-guard'}, "asc-guard"),
    ],
)
def test_hook_prefix(
    monkeypatch: pytest.MonkeyPatch, found: dict[str, str], expected: str
) -> None:
    monkeypatch.setattr(
        "mcp_security_review.guard.install.shutil.which", lambda name: found.get(name)
    )
    assert hook_prefix() == expected


@pytest.mark.parametrize(
    "command",
    [
        "asc-guard hook pre-tool-use",
        GATE + UVX_PREFIX + " hook post-tool-use",
        "C:/Users/me/.local/bin/asc-guard.EXE hook --client cursor pre-tool-use",
        '"/home/u/my projects/.venv/bin/asc-guard" hook user-prompt',
    ],
)
def test_every_form_of_our_command_is_recognised(command: str) -> None:
    # Reinstalling must replace these, not add a second copy.
    assert is_guard_command(command)
    assert not is_guard_command("./my-asc-guard-wrapper.sh")


# --- the plugin turns the guard on --------------------------------------------


def test_plugin_asks_for_the_typesafe_key() -> None:
    manifest = Path(__file__).parents[3] / ".claude-plugin" / "plugin.json"
    option = json.loads(manifest.read_text())["userConfig"]["typesafe_api_key"]
    assert option["type"] == "string" and option["sensitive"] is True
    assert option.get("required") is not True  # leaving it empty keeps the guard off
