# AI Security Crew

[![Run Tests](https://github.com/Srajangpt1/ai_security_crew/actions/workflows/tests.yml/badge.svg)](https://github.com/Srajangpt1/ai_security_crew/actions/workflows/tests.yml)
![License](https://img.shields.io/github/license/Srajangpt1/ai_security_crew)

A lightweight MCP server for security reviews built for vibe coding — injects security requirements prior to code generation, scans dependencies for CVEs, and verifies generated code, all without breaking your coding rhythm.

**Jump to installation:**
- [MCP Server](#quick-start) — full feature set with CVE scanning and threat modeling
- [Claude Code Plugin](#claude-code-plugin) — install 3 security skills globally in Claude Code (no MCP server needed)
- [Claude Code Skills only](#claude-code-skills) — manually add slash commands to a specific project

---

## Claude Code Plugin

Install all three security skills directly into Claude Code — no MCP server and no configuration required.

```
/plugin install Srajangpt1/ai_security_crew
```

This gives you three commands available in any project:

| Command | When to use |
|---------|-------------|
| `/sec-review` | Before coding — get risk level, OWASP guidelines, and a security prompt for AI code generation |
| `/verify-code` | After coding — review code for vulnerabilities with a checklist and prioritized fixes |
| `/threat-model` | For new features — identify threats with evidence links, mitigations, and optional `threat-model.md` |

---

## Claude Code Skills

If you prefer to add the skills to a specific project only (instead of globally), clone this repo and the slash commands in `.claude/commands/` are available automatically in Claude Code when working in the project directory.

---

## Tools

### Pre-coding
| Tool | When to Use |
|------|-------------|
| `lightweight_security_review` | Before any coding task — pick the components involved, get the threats to guard against and the countermeasures to build in |
| `perform_threat_model` | For significant new features — start a structured threat model from the library's known threats for the same components |

### Dependency security
| Tool | When to Use |
|------|-------------|
| `verify_packages` | When adding packages — confirm they exist with valid versions (catches hallucinated package names) |
| `scan_dependencies` | When adding packages — scan for CVEs; the agent checks reachability in your code |

### Post-coding
| Tool | When to Use |
|------|-------------|
| `verify_code_security` | After generating code — get a checklist aimed at the components' threats; the tool never receives your code, your agent reviews it against the checklist |

### Threat model persistence
| Tool | When to Use |
|------|-------------|
| `update_threat_model_file` | After `perform_threat_model` — write the threat model to `threat-model.md` in the repo |

## Agent Workflow

The server automatically sends workflow instructions to any connecting agent (Claude, Cursor, etc.) via the MCP `initialize` handshake. Agents will follow this workflow without additional configuration:

1. **Before coding** — call `lightweight_security_review`. If the task comes from a ticket or page link (Jira, Confluence, Linear, GitHub issues, and so on), the agent first fetches it with the matching MCP server you have connected and passes the details in
2. **When adding packages** — call `verify_packages`, then `scan_dependencies` with the code that uses them
3. **After generating code** — call `verify_code_security` with the same components and review your code against the checklist it returns
4. **For significant features** — call `perform_threat_model` and persist with `update_threat_model_file`

## Dependency Scanning

`scan_dependencies` uses [OSV.dev](https://osv.dev) to find CVEs. No code is sent to the tool. Each finding carries a `reachability_check`: the affected symbols OSV lists (or `no_symbol_data`), the fixed version, and a question. Your coding agent answers it by reading its own code, and upgrades when the symbols are used or it cannot tell.

## Quick Start

### 1. Build the image

```bash
docker build -t mcp-security-review:latest .
```

### 2. Configure your IDE

Add to your MCP config (Claude Desktop, Cursor, etc.):

```json
{
  "mcpServers": {
    "sec-review": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "mcp-security-review:latest"
      ]
    }
  }
}
```

### HTTP Transport

Run as a persistent HTTP service instead of stdio:

```bash
# Streamable HTTP (recommended)
docker run --rm -p 8000:8000 mcp-security-review:latest --transport streamable-http

# SSE
docker run --rm -p 8000:8000 mcp-security-review:latest --transport sse
```

## Threat Library

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

Pre-commit hooks enforce code quality (Ruff, Prettier, Pyright). Run `uv run pytest` before submitting.

## Security

Never commit API tokens. See [SECURITY.md](SECURITY.md) for best practices.

## License

Licensed under MIT — see [LICENSE](LICENSE).
