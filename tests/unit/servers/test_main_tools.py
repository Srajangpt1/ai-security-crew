"""Tests for the tools and instructions exposed by the main server."""

import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from mcp_security_review.library import builtin_library
from mcp_security_review.servers.main import (
    AGENT_INSTRUCTIONS,
    INSTRUCTIONS_LIMIT,
    main_mcp,
)

EXPECTED_TOOLS = {
    "general_lightweight_security_review",
    "general_project_context",
    "general_verify_code_security",
    "sca_assess_packages",
    "sca_lookup_vulnerability",
    "sca_scan_dependencies",
    "sca_verify_packages",
    "threatmodel_attack_technique",
    "threatmodel_perform_threat_model",
    "threatmodel_update_threat_model_file",
}


@pytest.mark.anyio
async def test_server_exposes_only_security_tools() -> None:
    tools = await main_mcp.get_tools()

    assert set(tools) == EXPECTED_TOOLS


def test_instructions_name_every_workflow_tool() -> None:
    for name in EXPECTED_TOOLS:
        assert name in AGENT_INSTRUCTIONS


def test_instructions_describe_the_two_call_review() -> None:
    assert "second time" in AGENT_INSTRUCTIONS
    assert "`components`" in AGENT_INSTRUCTIONS


def test_instructions_pass_the_same_components_to_later_tools() -> None:
    assert "same `components`" in AGENT_INSTRUCTIONS


def test_instructions_point_to_connected_ticket_tools() -> None:
    assert "ticket" in AGENT_INSTRUCTIONS
    assert "MCP server you have connected" in AGENT_INSTRUCTIONS
    # Removed tools must not be advertised.
    assert "assess_ticket_security" not in AGENT_INSTRUCTIONS
    assert "search_previous_threat_models" not in AGENT_INSTRUCTIONS


REPO_ROOT = Path(__file__).resolve().parents[3]


async def call(tool: str, **args: Any) -> dict[str, Any]:
    async with Client(main_mcp) as client:
        result = await client.call_tool(tool, args)
    items = result if isinstance(result, list) else result.content
    return json.loads(items[0].text)


def test_instructions_within_claude_code_limit() -> None:
    # Claude Code truncates server instructions at 2048 characters.
    assert INSTRUCTIONS_LIMIT == 2048
    assert len(AGENT_INSTRUCTIONS) <= INSTRUCTIONS_LIMIT


def test_instructions_cover_actions_images_and_upgrade_now() -> None:
    assert "upgrade_now" in AGENT_INSTRUCTIONS
    assert "Actions" in AGENT_INSTRUCTIONS
    assert "image" in AGENT_INSTRUCTIONS
    first = AGENT_INSTRUCTIONS.index("general_project_context")
    assert first < AGENT_INSTRUCTIONS.index("general_lightweight_security_review")


@pytest.mark.anyio
async def test_write_tool_refused_in_read_only_even_by_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("READ_ONLY_MODE", "true")
    target = tmp_path / "threat-model.md"

    data = await call(
        "threatmodel_update_threat_model_file",
        threat_model_json=json.dumps({"title": "T", "threats": []}),
        file_path=str(target),
    )

    assert data["success"] is False
    assert data["error"]["code"] == "read_only_mode"
    assert "threatmodel_update_threat_model_file" in data["error"]["message"]
    assert not target.exists()


@pytest.mark.anyio
async def test_read_tools_still_work_in_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("READ_ONLY_MODE", "true")

    data = await call("general_lightweight_security_review", task_description="x")

    assert data["success"] is True


@pytest.mark.anyio
async def test_disabled_tool_refused_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENABLED_TOOLS", "general_lightweight_security_review")

    refused = await call("threatmodel_attack_technique", technique_id="T1190")
    allowed = await call("general_lightweight_security_review", task_description="x")

    assert refused["success"] is False
    assert refused["error"]["code"] == "tool_disabled"
    assert allowed["success"] is True


def test_readme_uses_prefixed_names() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    for name in EXPECTED_TOOLS:
        assert name in readme
    for bare in ("`verify_packages`", "`scan_dependencies`", "`perform_threat_model`"):
        assert bare not in readme


def test_readme_counts_match_the_library() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    library = builtin_library()

    assert f"**{len(library.menu())} components**" in readme
    assert f"**{len(library.threats)} threats**" in readme
    assert f"**{len(library.countermeasures)} countermeasures**" in readme


def test_agents_md_workflow_matches_instructions() -> None:
    agents = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")

    for name in EXPECTED_TOOLS:
        assert name in AGENT_INSTRUCTIONS
        assert name in agents
    ecosystems = next(line for line in agents.splitlines() if '"pypi"' in line)
    for eco in ('"npm"', '"github-actions"', '"container"'):
        assert eco in ecosystems
