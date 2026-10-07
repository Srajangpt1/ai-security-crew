"""Normalized views of coding-agent configuration.

Env and header values are never stored, only their names.
"""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class McpServerEntry:
    """One MCP server declared in an agent config file."""

    client: str
    scope: str  # "project" or "user"
    source_file: str
    json_pointer: str
    name: str
    transport: str  # "stdio", "http", "sse", or the raw declared type
    command: str | None = None
    args: list[str] = field(default_factory=list)
    url: str | None = None
    env_keys: list[str] = field(default_factory=list)
    header_keys: list[str] = field(default_factory=list)


@dataclass
class AgentSettings:
    """Permission, hook and MCP approval settings from one settings file."""

    client: str
    scope: str
    source_file: str
    allow: list[str] = field(default_factory=list)
    ask: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    default_mode: str | None = None
    hooks: dict[str, Any] = field(default_factory=dict)
    mcp_auto_enable: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A problem found while discovering or checking configs."""

    rule_id: str
    source_file: str
    message: str


@dataclass
class DiscoveryResult:
    """Everything discovered for one project root."""

    project_root: str
    files_scanned: list[str] = field(default_factory=list)
    mcp_servers: list[McpServerEntry] = field(default_factory=list)
    settings: list[AgentSettings] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict."""
        return asdict(self)
