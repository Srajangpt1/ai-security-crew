"""The asc-guard command."""

import json
import os
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_security_review.guard.cli import main
from mcp_security_review.guard.install import GATE, UVX_PREFIX, build_hooks, install

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
    """The asc-guard-managed events in hooks.json must match the installer.

    hooks.json also carries a SessionStart entry for the fetch-intel
    prefetch, which build_hooks (asc-guard's own events only) does not
    generate, so this checks those events rather than the whole file.
    """
    plugin = Path(__file__).parents[3] / "hooks" / "hooks.json"
    hooks = json.loads(plugin.read_text())["hooks"]
    for event, groups in build_hooks(UVX_PREFIX).items():
        assert hooks[event] == groups


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
