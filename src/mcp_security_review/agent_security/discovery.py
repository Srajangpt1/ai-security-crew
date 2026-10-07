"""Find coding-agent config files in a project and the user's home."""

import os
from pathlib import Path

from .models import DiscoveryResult, Finding
from .parsers import agent_settings, load_config, mcp_servers, pointer_token

# Tests point this at a fixture directory instead of the real home.
HOME_ENV_VAR = "AGENTSEC_HOME"

# (client, path relative to the scope root, key holding MCP servers).
# A key of None marks a Claude Code settings file.
PROJECT_FILES: list[tuple[str, str, str | None]] = [
    # https://code.claude.com/docs/en/mcp
    ("claude-code", ".mcp.json", "mcpServers"),
    # https://code.claude.com/docs/en/settings
    ("claude-code", ".claude/settings.json", None),
    ("claude-code", ".claude/settings.local.json", None),
    # https://cursor.com/docs/context/mcp
    ("cursor", ".cursor/mcp.json", "mcpServers"),
    # https://code.visualstudio.com/docs/copilot/customization/mcp-servers
    ("vscode", ".vscode/mcp.json", "servers"),
]

USER_FILES: list[tuple[str, str, str | None]] = [
    # https://code.claude.com/docs/en/mcp (projects.<path>.mcpServers is
    # read separately, see _claude_json_project_servers)
    ("claude-code", ".claude.json", "mcpServers"),
    # https://code.claude.com/docs/en/settings
    ("claude-code", ".claude/settings.json", None),
    # https://modelcontextprotocol.io/docs/develop/connect-local-servers
    # ponytail: Windows path assumes the default %APPDATA% under the home dir.
    (
        "claude-desktop",
        "Library/Application Support/Claude/claude_desktop_config.json",
        "mcpServers",
    ),
    (
        "claude-desktop",
        "AppData/Roaming/Claude/claude_desktop_config.json",
        "mcpServers",
    ),
    # https://cursor.com/docs/context/mcp
    ("cursor", ".cursor/mcp.json", "mcpServers"),
    # Windsurf, now documented under Devin:
    # https://docs.devin.ai/desktop/cascade/mcp
    # ponytail: ignores XDG_CONFIG_HOME, read it if users report misses.
    ("windsurf", ".codeium/windsurf/mcp_config.json", "mcpServers"),  # legacy
    ("windsurf", ".config/devin/mcp_config.json", "mcpServers"),
    ("windsurf", "AppData/Roaming/devin/mcp_config.json", "mcpServers"),
    # https://learn.chatgpt.com/docs/extend/mcp?surface=cli
    # ponytail: ignores CODEX_HOME, add it when someone relocates ~/.codex.
    ("codex", ".codex/config.toml", "mcp_servers"),
]


def _home() -> Path:
    return Path(os.environ.get(HOME_ENV_VAR) or Path.home())


def _is_path(key: str, path: Path) -> bool:
    try:
        return Path(key).resolve() == path
    except (OSError, ValueError):  # e.g. a NUL byte in the key
        return False


def _claude_json_project_servers(
    data: dict, project_root: Path, result: DiscoveryResult, source_file: str
) -> None:
    """Add local-scope servers stored under projects.<path> in ~/.claude.json."""
    projects = data.get("projects")
    if not isinstance(projects, dict):
        return
    for key, entry in projects.items():
        if isinstance(entry, dict) and _is_path(key, project_root):
            result.mcp_servers += mcp_servers(
                entry.get("mcpServers"),
                "claude-code",
                "project",
                source_file,
                f"/projects/{pointer_token(key)}/mcpServers",
            )


def discover(
    project_root: str | Path,
    include_user_scope: bool = True,  # noqa: FBT001, FBT002
) -> DiscoveryResult:
    """Find and normalize every known agent config for a project.

    Args:
        project_root: Repository root to scan for project-scope configs.
        include_user_scope: Also scan the home directory (or $AGENTSEC_HOME).

    Returns:
        DiscoveryResult with MCP servers, settings and parse findings.
    """
    root = Path(project_root).resolve()
    result = DiscoveryResult(project_root=str(root))

    targets = [(root / rel, c, "project", key) for c, rel, key in PROJECT_FILES]
    if include_user_scope:
        home = _home()
        targets += [(home / rel, c, "user", key) for c, rel, key in USER_FILES]

    for path, client, scope, key in targets:
        if not path.is_file():
            continue
        source_file = str(path)
        result.files_scanned.append(source_file)
        try:
            data = load_config(path)
            if key is None:
                settings = agent_settings(data, client, scope, source_file)
                result.settings.append(settings)
                continue
            result.mcp_servers += mcp_servers(
                data.get(key), client, scope, source_file, f"/{key}"
            )
            if client == "claude-code" and path.name == ".claude.json":
                _claude_json_project_servers(data, root, result, source_file)
        # RecursionError: deeply nested input, which a hostile repo can plant.
        except (OSError, ValueError, RecursionError) as e:
            # Error text can echo file contents, so only the error type is kept.
            result.findings.append(
                Finding(
                    "config-unparseable",
                    source_file,
                    f"Could not parse config ({type(e).__name__})",
                )
            )

    return result
