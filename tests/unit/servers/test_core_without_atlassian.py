"""The core server must import and run without the optional Atlassian extra."""

import json
import subprocess
import sys
import textwrap

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
    print(json.dumps(sorted(tools)))
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

    tools = json.loads(result.stdout.strip().splitlines()[-1])
    prefixes = {name.split("_", 1)[0] for name in tools}

    assert tools, "expected core tools to be registered"
    assert prefixes <= {"general", "threatmodel", "sca"}, prefixes
    assert not any(name.startswith(("jira", "confluence")) for name in tools)
