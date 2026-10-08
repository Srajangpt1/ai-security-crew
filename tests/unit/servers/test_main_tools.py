"""Tests for the tools and instructions exposed by the main server."""

import pytest

from mcp_security_review.servers.main import AGENT_INSTRUCTIONS, main_mcp

EXPECTED_TOOLS = {
    "general_lightweight_security_review",
    "general_verify_code_security",
    "sca_scan_dependencies",
    "sca_verify_packages",
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


def test_instructions_point_to_connected_ticket_tools() -> None:
    assert "ticket" in AGENT_INSTRUCTIONS
    assert "MCP server you have connected" in AGENT_INSTRUCTIONS
    # Removed tools must not be advertised.
    assert "assess_ticket_security" not in AGENT_INSTRUCTIONS
    assert "search_previous_threat_models" not in AGENT_INSTRUCTIONS
