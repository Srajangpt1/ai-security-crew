"""Load agent config files and normalize their contents."""

import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import json5

from .models import AgentSettings, McpServerEntry

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

# Claude Code settings keys that approve project MCP servers without a prompt.
# https://code.claude.com/docs/en/settings-reference
MCP_AUTO_ENABLE_KEYS = (
    "enableAllProjectMcpServers",
    "enabledMcpjsonServers",
    "disabledMcpjsonServers",
)
PERMISSION_KEYS = ("allow", "ask", "deny", "defaultMode")
TRANSPORT_ALIASES = {"streamable-http": "http", "streamable_http": "http"}
JSON5_MAX_CHARS = 256_000


def load_config(path: Path) -> dict[str, Any]:
    """Parse a JSON, JSON-with-comments or TOML file into a dict.

    Raises:
        OSError: The file can't be read.
        ValueError: The file isn't valid or its top level isn't an object.
    """
    text = path.read_text(encoding="utf-8-sig")  # editors on Windows add a BOM
    if path.suffix == ".toml":
        data = tomllib.loads(text)
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # json5 is pure Python (~11 s per MB), so it only handles small
            # files with comments or trailing commas. The cap stops a planted
            # oversized repo file from stalling the scan.
            if len(text) > JSON5_MAX_CHARS:
                raise ValueError("too large to parse as JSON5") from None
            data = json5.loads(text)
    if not isinstance(data, dict):
        raise ValueError("top-level value is not an object")
    return data


def pointer_token(key: str) -> str:
    """Escape one JSON pointer reference token (RFC 6901)."""
    return key.replace("~", "~0").replace("/", "~1")


def _keys(value: Any) -> list[str]:
    return sorted(str(k) for k in value) if isinstance(value, dict) else []


def _redact(value: Any) -> Any:
    """Replace every nested `env` or `headers` mapping with its sorted keys.

    HTTP hooks carry `headers`, and their values can be literal tokens.
    """
    if isinstance(value, dict):
        return {
            k: _keys(v) if k in ("env", "headers") else _redact(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _strings(value: Any) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list) else []


def _transport(cfg: dict[str, Any], url: str | None) -> str:
    declared = cfg.get("type") or cfg.get("transport")
    if isinstance(declared, str) and declared:
        return TRANSPORT_ALIASES.get(declared.lower(), declared.lower())
    if cfg.get("command"):
        return "stdio"
    # ponytail: suffix guess when no type is declared, read the client's
    # own detection rules if a client starts disagreeing.
    try:
        path = urlsplit(str(url)).path if url else ""
    except ValueError:  # malformed URL, e.g. "http://[bad"
        path = ""
    return "sse" if path.rstrip("/").endswith("/sse") else "http"


def mcp_servers(
    servers: Any, client: str, scope: str, source_file: str, pointer: str
) -> list[McpServerEntry]:
    """Normalize a name -> server-config mapping. Values of env and headers
    are dropped; only their names are kept.
    """
    if not isinstance(servers, dict):
        return []
    entries = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        url = cfg.get("url") or cfg.get("serverUrl")  # serverUrl: Windsurf
        env_keys = _keys(cfg.get("env")) + _strings(cfg.get("env_vars"))  # Codex
        header_keys = (
            _keys(cfg.get("headers"))
            + _keys(cfg.get("http_headers"))  # Codex
            + _keys(cfg.get("env_http_headers"))  # Codex
        )
        if cfg.get("bearer_token_env_var"):  # Codex
            header_keys.append("Authorization")
        entries.append(
            McpServerEntry(
                client=client,
                scope=scope,
                source_file=source_file,
                json_pointer=f"{pointer}/{pointer_token(str(name))}",
                name=str(name),
                transport=_transport(cfg, url),
                command=str(cfg["command"]) if cfg.get("command") else None,
                args=_strings(cfg.get("args")),
                url=str(url) if url else None,
                env_keys=sorted(set(env_keys)),
                header_keys=sorted(set(header_keys)),
            )
        )
    return entries


def agent_settings(
    data: dict[str, Any], client: str, scope: str, source_file: str
) -> AgentSettings:
    """Normalize a Claude Code settings file. `env` is dropped entirely."""
    permissions = data.get("permissions")
    permissions = permissions if isinstance(permissions, dict) else {}
    hooks = data.get("hooks")

    raw = {
        k: v
        for k, v in data.items()
        if k not in ("permissions", "hooks", "env", *MCP_AUTO_ENABLE_KEYS)
    }
    extra_permissions = {
        k: v for k, v in permissions.items() if k not in PERMISSION_KEYS
    }
    if extra_permissions:
        raw["permissions"] = extra_permissions

    default_mode = permissions.get("defaultMode")
    return AgentSettings(
        client=client,
        scope=scope,
        source_file=source_file,
        allow=_strings(permissions.get("allow")),
        ask=_strings(permissions.get("ask")),
        deny=_strings(permissions.get("deny")),
        default_mode=str(default_mode) if default_mode else None,
        hooks=_redact(hooks) if isinstance(hooks, dict) else {},
        mcp_auto_enable={k: data[k] for k in MCP_AUTO_ENABLE_KEYS if k in data},
        raw=_redact(raw),
    )
