"""Tests for agent config discovery and normalization."""

import json
import shutil
from pathlib import Path

import pytest

from mcp_security_review.agent_security import discover
from mcp_security_review.agent_security.discovery import HOME_ENV_VAR

FIXTURES = Path(__file__).parents[2] / "fixtures" / "agent_configs"


@pytest.fixture
def configs(tmp_path, monkeypatch):
    shutil.copytree(FIXTURES, tmp_path, dirs_exist_ok=True)
    project = tmp_path / "project"
    # Local-scope servers live in ~/.claude.json keyed by the project's path.
    claude_json = tmp_path / "home" / ".claude.json"
    data = json.loads(claude_json.read_text())
    data["projects"][str(project)] = {
        "mcpServers": {"local-only": {"type": "sse", "url": "http://localhost:9/sse"}}
    }
    claude_json.write_text(json.dumps(data))
    monkeypatch.setenv(HOME_ENV_VAR, str(tmp_path / "home"))
    return project


def _servers(result):
    return {(s.client, s.scope, s.name): s for s in result.mcp_servers}


def test_every_client_and_scope_normalizes(configs):
    servers = _servers(discover(configs))

    assert set(servers) == {
        ("claude-code", "project", "dbhub"),
        ("claude-code", "project", "remote/api"),
        ("claude-code", "project", "local-only"),
        ("claude-code", "user", "user-server"),
        ("cursor", "project", "sse-server"),
        ("cursor", "user", "cursor-global"),
        ("vscode", "project", "github"),
        ("claude-desktop", "user", "filesystem"),
        ("windsurf", "user", "windsurf-remote"),
        ("codex", "user", "context7"),
        ("codex", "user", "figma"),
    }

    dbhub = servers[("claude-code", "project", "dbhub")]
    assert (dbhub.transport, dbhub.command, dbhub.args, dbhub.env_keys) == (
        "stdio",
        "npx",
        ["-y", "@bytebase/dbhub"],
        ["DATABASE_URL"],
    )
    assert dbhub.json_pointer == "/mcpServers/dbhub"

    remote = servers[("claude-code", "project", "remote/api")]
    assert remote.transport == "http"
    assert remote.header_keys == ["Authorization"]
    assert remote.json_pointer == "/mcpServers/remote~1api"

    local = servers[("claude-code", "project", "local-only")]
    assert local.source_file.endswith(".claude.json")
    assert local.json_pointer.endswith("/mcpServers/local-only")

    assert servers[("cursor", "project", "sse-server")].transport == "sse"
    assert servers[("cursor", "user", "cursor-global")].transport == "stdio"
    assert servers[("vscode", "project", "github")].header_keys == ["Authorization"]
    windsurf = servers[("windsurf", "user", "windsurf-remote")]
    assert (windsurf.transport, windsurf.url) == ("http", "https://ws.example.com/mcp")

    context7 = servers[("codex", "user", "context7")]
    assert context7.json_pointer == "/mcp_servers/context7"
    assert context7.env_keys == ["CONTEXT7_KEY", "PATH_HINT"]
    figma = servers[("codex", "user", "figma")]
    assert (figma.transport, figma.header_keys) == ("http", ["Authorization", "X-Team"])


def test_settings_normalize(configs):
    result = discover(configs)
    settings = {(s.scope, Path(s.source_file).name): s for s in result.settings}

    shared = settings[("project", "settings.json")]
    assert shared.allow == ["Bash(npm run test:*)"]
    assert shared.ask == ["Bash(git push:*)"]
    assert shared.deny == ["Read(./.env)"]
    assert shared.default_mode == "acceptEdits"
    assert shared.hooks["PreToolUse"][1]["hooks"][0]["headers"] == ["Authorization"]
    assert shared.mcp_auto_enable == {"enableAllProjectMcpServers": True}
    assert shared.raw == {
        "model": "opus",
        "permissions": {"additionalDirectories": ["../docs"]},
    }

    local = settings[("project", "settings.local.json")]
    assert local.mcp_auto_enable == {"enabledMcpjsonServers": ["dbhub"]}
    assert settings[("user", "settings.json")].default_mode == "bypassPermissions"


def test_malformed_file_is_a_finding_not_a_crash(configs):
    findings = discover(configs).findings

    assert [(f.rule_id, Path(f.source_file).name) for f in findings] == [
        ("config-unparseable", "mcp_config.json")
    ]


def test_utf8_bom_is_accepted(tmp_path, monkeypatch):
    monkeypatch.setenv(HOME_ENV_VAR, str(tmp_path / "home"))
    (tmp_path / ".mcp.json").write_bytes(b'\xef\xbb\xbf{"mcpServers": {"a": {}}}')

    result = discover(tmp_path)

    assert (result.findings, [s.name for s in result.mcp_servers]) == ([], ["a"])


def test_deeply_nested_file_is_a_finding_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setenv(HOME_ENV_VAR, str(tmp_path / "home"))
    depth = 100_000
    (tmp_path / ".mcp.json").write_text("[" * depth + "]" * depth)

    findings = discover(tmp_path).findings

    assert [(f.rule_id, f.message) for f in findings] == [
        ("config-unparseable", "Could not parse config (RecursionError)")
    ]


def test_oversized_jsonc_is_a_finding_not_a_slow_parse(tmp_path, monkeypatch):
    monkeypatch.setenv(HOME_ENV_VAR, str(tmp_path / "home"))
    padding = "// pad\n" * 40_000  # ~280 KB, over the json5 cap
    (tmp_path / ".mcp.json").write_text(padding + '{"mcpServers": {}}')

    findings = discover(tmp_path).findings

    assert [f.rule_id for f in findings] == ["config-unparseable"]


def test_bad_claude_json_project_key_is_skipped(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".claude.json").write_text(
        json.dumps({"projects": {"C:\x00bad": {"mcpServers": {"x": {}}}}})
    )
    monkeypatch.setenv(HOME_ENV_VAR, str(home))

    result = discover(tmp_path)

    assert (result.mcp_servers, result.findings) == ([], [])


@pytest.mark.parametrize(
    ("url", "transport"),
    [
        ("https://x/sse", "sse"),
        ("https://x/sse/", "sse"),
        ("https://x/mcp?next=/sse", "http"),
        ("http://[bad", "http"),
    ],
)
def test_transport_guess_uses_url_path(tmp_path, monkeypatch, url, transport):
    monkeypatch.setenv(HOME_ENV_VAR, str(tmp_path / "home"))
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"a": {"url": url}}}))

    assert discover(tmp_path).mcp_servers[0].transport == transport


def test_no_env_or_header_values_in_output(configs):
    output = json.dumps(discover(configs).to_dict())

    assert "SECRET-VALUE" not in output
    assert "someone@example.com" not in output


def test_user_scope_can_be_skipped(configs):
    result = discover(configs, include_user_scope=False)

    home = (configs.parent / "home").resolve()
    assert {s.scope for s in result.mcp_servers} == {"project"}
    assert not any(Path(f).resolve().is_relative_to(home) for f in result.files_scanned)
