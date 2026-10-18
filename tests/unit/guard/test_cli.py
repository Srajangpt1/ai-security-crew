"""The asc-guard command."""

import json
import os
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
    [({}, 0), ({"TYPESAFE_API_KEY": "k"}, 1), ({"ASC_GUARD_ENABLE": "1"}, 1)],
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


# --- install: keeping the settings file safe ----------------------------------

CONFIG = Path(".claude") / "settings.json"
# Someone's own hooks, already in the file before the guard is installed.
EXISTING: dict[str, Any] = {
    "model": "x",
    "hooks": {
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "./a"}]}
        ],
        "Stop": [{"hooks": [{"type": "command", "command": "./b"}]}],
    },
}


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.chdir(root)
    return root


@pytest.mark.parametrize(
    "text", ["{oops", "[]", '{"hooks": []}', '{"hooks": {"PreToolUse": {}}}']
)
def test_install_refuses_a_malformed_config_and_leaves_it_alone(
    project: Path, text: str
) -> None:
    path = project / CONFIG
    path.parent.mkdir()
    path.write_text(text)
    code, out = run("install")
    assert code == 1 and path.name in out
    assert path.read_text() == text


def test_a_failed_write_keeps_the_old_config(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = project / CONFIG
    path.parent.mkdir()
    original = json.dumps(EXISTING)
    path.write_text(original)
    real_write = Path.write_text

    def write_half_then_fail(self: Path, data: str, *a: Any, **k: Any) -> int:
        real_write(self, data[:10], *a, **k)
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_text", write_half_then_fail)
    result = CliRunner().invoke(main, ["install"])
    monkeypatch.undo()
    assert result.exit_code == 1 and "disk full" in result.output
    assert isinstance(result.exception, SystemExit)  # an error message, no traceback
    assert path.read_text() == original
    assert [p.name for p in path.parent.iterdir()] == [path.name]


def test_an_unwritable_location_is_a_clean_error(project: Path) -> None:
    (project / CONFIG.parent).write_text("a file where the folder goes")
    result = CliRunner().invoke(main, ["install"])
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)


def test_install_accepts_a_file_saved_with_a_bom(project: Path) -> None:
    path = project / CONFIG
    path.parent.mkdir()
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(EXISTING).encode())
    assert run("install")[0] == 0
    assert json.loads(path.read_text("utf-8"))["hooks"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_install_keeps_the_file_private(project: Path) -> None:
    path = project / CONFIG
    path.parent.mkdir()
    path.write_text("{}")
    path.chmod(0o600)
    run("install")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_install_writes_through_a_symlink(project: Path) -> None:
    real = project / "dotfiles" / "config.json"
    real.parent.mkdir()
    real.write_text("{}")
    link = project / CONFIG
    link.parent.mkdir()
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("this system does not allow symlinks")
    assert run("install")[0] == 0
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
        "C:/Users/me/.local/bin/asc-guard.EXE hook pre-tool-use",
        '"/home/u/my projects/.venv/bin/asc-guard" hook user-prompt',
    ],
)
def test_every_form_of_our_command_is_recognised(command: str) -> None:
    # Reinstalling must replace these, not add a second copy.
    assert is_guard_command(command)
    assert not is_guard_command("./my-asc-guard-wrapper.sh")


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


def test_an_unexpected_error_fails_open(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(event: object) -> None:
        raise KeyError("surprise")

    monkeypatch.setenv("ASC_GUARD_ENABLE", "1")
    monkeypatch.setattr("mcp_security_review.guard.engine.handle", broken)
    result = CliRunner().invoke(main, ["hook", "pre-tool-use"], input=json.dumps(PRE))
    assert result.exit_code == 0 and "skipped" in result.output
    assert not isinstance(result.exception, KeyError)
