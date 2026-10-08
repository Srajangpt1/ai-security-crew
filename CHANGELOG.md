# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Changed — code review and threat modeling use the threat library
- `verify_code_security` takes `components`, `data_handled`, `language`, and `project_root` instead of `security_context`. Its focus areas and checklist come from the library's threats and countermeasures for the components you name, plus the language hints and a short baseline. The language is chosen by the `language` argument or the file extension, never by scanning the code
- `perform_threat_model` takes `components`, `data_handled`, and `project_root`, and returns `known_threats` (library threats and countermeasures, or the component menu) in place of `security_signals`
- Language hints (focus areas, checks, file extensions) now live in `library/languages.yaml` and can be extended per project; countermeasures can be marked `baseline: true`
- Removed the keyword analyzer (`security/analyzer.py`) and all regex-based technology detection

### Changed — threat library replaces the OWASP guideline files
- `lightweight_security_review` now takes two calls: the first returns a menu of components (file upload, database, login, and so on); the second takes `components` (and optionally `data_handled`) and returns the threats to guard against and the countermeasures to build in. The calling agent picks the components, so there is no keyword matching
- New built-in threat library in `src/mcp_security_review/library/`: 23 components, 83 threats (STRIDE, CWE), and 81 countermeasures that cite OWASP ASVS 5.0.0 requirement ids
- The risk level is the highest severity among the threats on the picked components; `data_handled` raises it one step. Threats that only come from implied components are listed separately under `also_consider`
- Teams can add or override components, threats, and countermeasures in `.ai-security-crew/library/*.yaml` (see `docs/ADDING_THREATS.md`)
- Tool parameters `include_guidelines` and `include_prompt_injection` are removed; `project_root` and `components` were added. Output is compact JSON, about 50-75% smaller on the example tasks
- Removed the 101 bundled OWASP cheat sheet files (about 2.3 MB), the guideline loader, `SecurityAssessment`, and the guideline scripts and docs. Added the `pyyaml` dependency
- The threat model tool still uses the keyword analyzer for its `security_signals`

### Removed — Jira and Confluence integration
- Removed the Jira and Confluence tools (`jira_get_issue`, `jira_assess_ticket_security`, `confluence_search`, `confluence_get_page`) and `threatmodel_search_previous_threat_models`, plus the `atlassian` extra, OAuth setup, Jira/Confluence CLI flags and environment variables
- Removed `providers/atlassian/`, `models/atlassian/`, `preprocessing/` and the Atlassian-only helpers in `utils/`; the `cachetools` dependency is gone too
- Agent workflow instructions now tell the agent to fetch tickets and pages (Jira, Confluence, Linear, GitHub issues, and so on) with whichever MCP server the user has connected, then pass the details in
- The core server now exposes 6 tools: `general_lightweight_security_review`, `general_verify_code_security`, `sca_verify_packages`, `sca_scan_dependencies`, `threatmodel_perform_threat_model`, `threatmodel_update_threat_model_file`
- `NOTICE` now lists only the shared utilities that remain adapted from mcp-atlassian

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
