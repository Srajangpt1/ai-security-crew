"""The core server must import and run without the optional Atlassian extra."""

import json
import subprocess
import sys
import textwrap

ATLASSIAN_TOOL_NAMES = [
    "jira_assess_ticket_security",
    "threatmodel_search_previous_threat_models",
]

BLOCKED_MODULES = [
    "atlassian",
    "bs4",
    "markdownify",
    "markdown",
    "md2conf",
    "keyring",
    "requests",
    "dateutil",
]

SCRIPT = textwrap.dedent(
    """
    import asyncio
    import json
    import sys

    for name in {blocked!r}:
        sys.modules[name] = None  # any import of these now raises ImportError

    from mcp_security_review.servers.main import main_mcp

    tools = asyncio.run(main_mcp.get_tools())
    print(json.dumps({{"tools": sorted(tools), "instructions": main_mcp.instructions}}))
    """
)


def test_core_tools_load_without_atlassian_extra() -> None:
    result = subprocess.run(
        [sys.executable, "-c", SCRIPT.format(blocked=BLOCKED_MODULES)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    payload = json.loads(result.stdout.strip().splitlines()[-1])
    tools = payload["tools"]
    prefixes = {name.split("_", 1)[0] for name in tools}

    assert tools, "expected core tools to be registered"
    assert prefixes <= {"general", "threatmodel", "sca"}, prefixes
    assert not any(name.startswith(("jira", "confluence")) for name in tools)

    instructions = payload["instructions"]
    assert "general_lightweight_security_review" in instructions
    for name in ATLASSIAN_TOOL_NAMES:
        assert name not in instructions


def test_instructions_mention_atlassian_tools_only_with_extra() -> None:
    from mcp_security_review.servers.main import build_agent_instructions

    with_extra = build_agent_instructions(atlassian=True)
    without_extra = build_agent_instructions(atlassian=False)

    for name in ATLASSIAN_TOOL_NAMES:
        assert name in with_extra
        assert name not in without_extra
    # Shared workflow is identical apart from the optional lines.
    assert "sca_verify_packages" in with_extra
    assert "sca_verify_packages" in without_extra
