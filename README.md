# AI Security Crew

[![Run Tests](https://github.com/Srajangpt1/ai-security-crew/actions/workflows/tests.yml/badge.svg)](https://github.com/Srajangpt1/ai-security-crew/actions/workflows/tests.yml)
![License](https://img.shields.io/github/license/Srajangpt1/ai-security-crew)

Security guidance for AI coding agents. Before your agent writes code, it gets the threats to guard against and the fixes to build in. When it adds packages, they are checked and scanned for CVEs. When it finishes, it reviews its own code against a checklist. No code leaves your agent: the tools return structured data and your agent makes the judgment.

## Install

Pick one. The skills work on their own. The MCP server adds the dependency checks and the full tool set.

### Option 1: Claude Code plugin (skills only)

```
/plugin marketplace add Srajangpt1/ai-security-crew
/plugin install mcp-security-review@ai-security-crew
```

You get three commands in any project:

| Command | When to use |
|---------|-------------|
| `/sec-review` | Before coding: risk level and a security prompt for the task |
| `/verify-code` | After coding: review the code with a checklist and prioritized fixes |
| `/threat-model` | For new features: threats, mitigations, and an optional `threat-model.md` |

### Option 2: MCP server

The server is not on PyPI. Run it straight from GitHub with [uv](https://docs.astral.sh/uv/):

**Claude Code**

```bash
claude mcp add sec-review -- uvx --from git+https://github.com/Srajangpt1/ai-security-crew mcp-security-review
```

**Cursor, Claude Desktop, Windsurf, and other MCP clients**

Add this to the client's MCP config (`.cursor/mcp.json`, `claude_desktop_config.json`, and so on):

```json
{
  "mcpServers": {
    "sec-review": {
      "command": "uvx",
      "args": [
        "--from", "git+https://github.com/Srajangpt1/ai-security-crew",
        "mcp-security-review"
      ]
    }
  }
}
```

**Docker instead of uv**

```bash
docker build -t mcp-security-review:latest .
```

```json
{
  "mcpServers": {
    "sec-review": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "mcp-security-review:latest"]
    }
  }
}
```

To run as an HTTP service instead of stdio, add `--transport streamable-http` (or `sse`) and publish port 8000:

```bash
docker run --rm -p 8000:8000 mcp-security-review:latest --transport streamable-http
```

The server sends its workflow to the connected agent when it starts, so there is nothing else to configure.

## What your agent sees

For the task "Let users upload profile photos", the agent picks the `file-upload` component and gets back, trimmed:

```json
{
  "assessment": {
    "risk_level": "high",
    "threats": [
      {"id": "upload-executable-file", "severity": "high", "cwe": ["CWE-434"],
       "name": "Attacker uploads a script that your server runs or serves"},
      {"id": "upload-path-traversal", "severity": "high", "cwe": ["CWE-22"],
       "name": "Attacker uses ../ in a filename to overwrite files"}
    ],
    "countermeasures": [
      {"id": "upload-allow-list", "effort": "low", "asvs": ["v5.0.0-5.2.2"],
       "name": "Allow only the file types you need",
       "how_to": "Check the extension and the real file content against an allow-list. Ignore the client's Content-Type."}
    ]
  }
}
```

The agent builds those countermeasures in, and after writing the code it reviews it against the checklist from `verify_code_security`.

## Tools

| Tool | When to use |
|------|-------------|
| `lightweight_security_review` | Before any coding task. Call once for a menu of components, then again with the ids that apply to get threats and countermeasures |
| `perform_threat_model` | For significant new features. Starts a structured threat model from the library's threats for the same components |
| `update_threat_model_file` | After `perform_threat_model`. Writes `threat-model.md` in the repo |
| `verify_packages` | When adding packages. Confirms they exist with valid versions, which catches hallucinated names |
| `scan_dependencies` | When adding packages. Scans for CVEs and asks the agent to check reachability in its own code |
| `verify_code_security` | After generating code. Returns a checklist aimed at the components' threats. It never receives your code |

Every failure comes back as `{"success": false, "error": {"code", "message", "hint"}}`.

## Agent workflow

1. **Before coding**: call `lightweight_security_review`. If the task comes from a ticket or page link (Jira, Confluence, Linear, GitHub issues, and so on), the agent first fetches it with the matching MCP server you have connected.
2. **When adding packages**: call `verify_packages`, then `scan_dependencies`.
3. **After generating code**: call `verify_code_security` with the same components and review the code against the checklist.
4. **For significant features**: call `perform_threat_model`, then `update_threat_model_file`.

## Dependency scanning

`scan_dependencies` uses [OSV.dev](https://osv.dev) to find CVEs. No code is sent to the tool. Each finding carries a `reachability_check`: the affected symbols OSV lists (or `no_symbol_data`), the fixed version, and a question. Your agent answers it by reading its own code, and upgrades when the symbols are used or it cannot tell.

## Threat library

`lightweight_security_review` is backed by a built-in library of **25 components**, **88 threats**, and **85 countermeasures** (web and API apps, plus LLM, agent, and MCP features). Threats carry STRIDE and CWE references (and OWASP MCP Top 10 ids for agent and MCP threats), and countermeasures cite [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS) requirement ids.

The agent calls the tool twice: the first call returns a menu of components, the second takes the ids that apply and returns the threats and countermeasures.

Add your own components, threats, and countermeasures in `.ai-security-crew/library/*.yaml` in your repo:

```yaml
components:
  - id: internal-sso
    name: Company SSO
    applies_when: The feature signs users in through our SSO.
threats:
  - id: sso-token-reuse
    name: A token for one app is reused on another
    components: [internal-sso]
    severity: high
    countermeasures: [validate-token-claims]
```

See [docs/ADDING_THREATS.md](docs/ADDING_THREATS.md) for the full format.

## Contributing

1. Check [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.
2. Make changes and submit a pull request.

Pre-commit hooks enforce code quality (Ruff and mypy). Run `uv run pytest` before submitting.

## Security

Never commit API tokens. See [SECURITY.md](SECURITY.md) for best practices.

## License

Licensed under MIT — see [LICENSE](LICENSE).
