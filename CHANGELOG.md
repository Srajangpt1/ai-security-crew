# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Changed — ownership and attribution
- Package metadata now lists Srajan Gupta as author with a security-focused description
- `LICENSE` keeps the upstream MIT notice and adds a copyright line for this project
- Added `NOTICE` listing code derived from sooperset/mcp-atlassian

### Added — SCA vulnerability scanning
- `verify_packages` tool: validates package names and versions against PyPI/npm registries; suggests closest match for hallucinated or misspelled packages
- `scan_dependencies` tool: queries [OSV.dev](https://osv.dev) for CVEs and performs reachability analysis on provided code snippets
- Reachability analysis pipeline:
  - Static check using OSV function-level symbols (`ecosystem_specific.imports`)
  - Keyword matching against vulnerability summaries (CamelCase, quoted terms, snake_case)
  - AI reachability via `ctx.sample()` — calls back to the host agent (Claude, Cursor) for ambiguous cases; no extra API key required
- Reachability statuses: `reachable`, `not_reachable`, `not_imported`, `uncertain`, `no_code_provided`
- Graceful degradation: if the MCP client doesn't support sampling, status remains `ai_analysis_required`

### Added — Threat modeling
- `perform_threat_model` tool: generates developer-focused threat models (STRIDE, attack surfaces, mitigations)
- `search_previous_threat_models` tool: searches Confluence for existing threat models to use as reference
- `update_threat_model_file` tool: writes or updates `threat-model.md` in the repository

### Added — Agent workflow instructions
- MCP server now sends workflow instructions to connecting agents via the `initialize` handshake (`instructions=` field)
- Agents automatically know when to call each tool without additional configuration
- `AGENTS.md` updated with full security tool workflow for repo contributors

### Changed
- `main.py` lint cleanup: resolved all pre-existing E501 violations

---

## [0.1.0] — Initial release

### Added
- `lightweight_security_review`: pre-coding security assessment with OWASP guidelines
- `assess_ticket_security`: pull security requirements from a Jira ticket
- `verify_code_security`: post-coding AI security review of generated code
- Jira and Confluence integration (read/write)
- OAuth 2.0, API token, and PAT authentication
- Docker image with multi-stage Alpine build
- 101 OWASP Cheat Sheets loaded as security guidelines
- Custom guideline support
