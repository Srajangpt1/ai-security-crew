# AI Security Crew

[![Run Tests](https://github.com/Srajangpt1/ai_security_crew/actions/workflows/tests.yml/badge.svg)](https://github.com/Srajangpt1/ai_security_crew/actions/workflows/tests.yml)
![License](https://img.shields.io/github/license/Srajangpt1/ai_security_crew)

A lightweight MCP server for security reviews built for vibe coding — injects security requirements prior to code generation, scans dependencies for CVEs, and verifies generated code, all without breaking your coding rhythm.

**Jump to installation:**
- [MCP Server](#quick-start) — full feature set with CVE scanning (with reachability) and threat modeling
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
| `lightweight_security_review` | Before any coding task — get security requirements and guidelines for your tech stack |
| `perform_threat_model` | For significant new features — generate a structured threat model (STRIDE, attack surfaces) |

### Dependency security
| Tool | When to Use |
|------|-------------|
| `verify_packages` | When adding packages — confirm they exist with valid versions (catches hallucinated package names) |
| `scan_dependencies` | When adding packages — scan for CVEs and check reachability in your code |

### Post-coding
| Tool | When to Use |
|------|-------------|
| `verify_code_security` | After generating code — AI-powered security review against OWASP guidelines |

### Threat model persistence
| Tool | When to Use |
|------|-------------|
| `update_threat_model_file` | After `perform_threat_model` — write the threat model to `threat-model.md` in the repo |

## Agent Workflow

The server automatically sends workflow instructions to any connecting agent (Claude, Cursor, etc.) via the MCP `initialize` handshake. Agents will follow this workflow without additional configuration:

1. **Before coding** — call `lightweight_security_review`. If the task comes from a ticket or page link (Jira, Confluence, Linear, GitHub issues, and so on), the agent first fetches it with the matching MCP server you have connected and passes the details in
2. **When adding packages** — call `verify_packages`, then `scan_dependencies` with the code that uses them
3. **After generating code** — call `verify_code_security` and follow the `review_prompt` to report findings
4. **For significant features** — call `perform_threat_model` and persist with `update_threat_model_file`

## Dependency Scanning

`scan_dependencies` uses [OSV.dev](https://osv.dev) to find CVEs and performs reachability analysis to determine if vulnerable code paths are actually called:

| Status | Meaning |
|--------|---------|
| `reachable` | Vulnerable function is called in your code — action required |
| `not_reachable` | Vulnerable function is not called |
| `not_imported` | Package is not imported at all |
| `uncertain` | AI analyzed the code but could not determine reachability |
| `no_code_provided` | No code snippets were passed to the tool |

Reachability is determined by (in order): OSV function-level symbols → keyword matching against the vuln summary → AI analysis via `ctx.sample()`.

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

## Security Guidelines

Includes **101 OWASP Cheat Sheets** loaded automatically into security assessments. Add your own org-specific guidelines:

```bash
python3 scripts/add_custom_guideline.py
```

Or manually create markdown files in `src/mcp_security_review/security/guidelines/docs/`:

```markdown
category: your_category
priority: high
tags: tag1, tag2, tag3

# Your Guideline Title
...
```

See [docs/ADDING_CUSTOM_GUIDELINES.md](docs/ADDING_CUSTOM_GUIDELINES.md) for details.

## Contributing

1. Check [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.
2. Make changes and submit a pull request.

Pre-commit hooks enforce code quality (Ruff, Prettier, Pyright). Run `uv run pytest` before submitting.

## Security

Never commit API tokens. See [SECURITY.md](SECURITY.md) for best practices.

## License

Licensed under MIT — see [LICENSE](LICENSE).
