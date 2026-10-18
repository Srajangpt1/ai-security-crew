# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added — asc-guard for Cursor
- `asc-guard install --client cursor` writes Cursor's `.cursor/hooks.json` (`--client claude-code` is the default). The guard judges shell and MCP calls before they run, and file writes and web fetches through `preToolUse`; Cursor cannot ask before those, so an ask there becomes a deny with an explanation.
- The Claude Code plugin asks for an optional TypeSafe API key when it is enabled, so installing the plugin is enough to turn the guard on. Leaving it empty keeps the guard off.
- Claude Code's hooks step aside when Cursor runs them, so a call is never judged twice.

### Fixed — asc-guard hardening
- The protected-file rule is much harder to get around. It now catches redirects after read-only commands (`cat x > .mcp.json`), `sh -c`/`eval`/`pwsh`/`cmd /c` wrappers including PowerShell's `-EncodedCommand`, interpreter one-liners and heredocs, `cd` followed by a relative path, globs and brace expansion, backslash paths, removing or replacing a config folder, different case (macOS), symlinks, Cursor's `target_file` argument and filesystem MCP servers. VS Code, Claude Desktop, Cursor hook scripts and the new Windsurf path are protected too. A command too long to check before the hook times out is blocked.
- The protected-file rule runs before anything else, so a bad `ASC_GUARD_*` setting can no longer switch it off.
- A malformed answer from Jev, an unreadable session file or a failure to save session state no longer crash the hook; the warning about injected content still reaches the agent when saving fails. Any unexpected error fails open with a message instead of a traceback.
- The hook reads its input as UTF-8 whatever the console code page, so non-English prompts are no longer garbled on Windows.
- `install` writes the full path of a lasting `asc-guard` (or of `uvx` when it runs from a throwaway uvx environment) instead of a bare name that the client may not find. It accepts files saved with a byte order mark, keeps the file's permissions, writes through symlinks, never truncates a file when a write fails, and refuses a file it would have to discard parts of.
- No wasted wait after the last failed Jev attempt.

### Changed — plugin packaging
- The Claude Code plugin now registers the MCP server (`sec-review`), so one install gives the tools, the skills and the guard hooks.
- The guard hooks check for `TYPESAFE_API_KEY` (or `ASC_GUARD_ENABLE`) before starting `uvx`. Without a key they exit at once instead of adding about a second to every tool call. `asc-guard install` writes the same check.
- Removed the duplicate `commands/` copies of the skills.
- When Jev cannot be reached, the guard no longer asks before shell, network and MCP calls. It steps aside and the client's own permission settings decide.
- Rewrote the three skills around the current tools: the component menu, threats and countermeasures for the picked components, the code review checklist that never receives code, and reachability checks on dependency findings. Each falls back to plain guidance when the tools are not available.

### Added — evaluation harness for asc-guard
- `tests/eval/` scores asc-guard against the agent-guard-bench cases: it judges them in parallel with several trials, saves Jev's raw answers with latency, token usage and cost, reports stop rate, false alarms, precision and accuracy per kind and source, and re-applies the policy to saved answers to try other thresholds without new API calls. See `docs/EVALUATION.md`.
- The Jev client now keeps the token usage and model name the API returns.

### Added — runtime guard for coding agents
- New `asc-guard` command with `hook`, `check` and `install`. Claude Code runs it before and after tool calls and when a prompt is submitted. Before a call it asks TypeSafe's Jev model four questions (risk, approval, user requested, from untrusted content) and answers allow, ask or deny. After a tool result it checks whether the content tries to instruct the agent, and remembers that so later calls that act on it are denied.
- The agent cannot edit agent config or hook files (`.claude/settings*.json`, `.mcp.json`, `.cursor/mcp.json` and similar). This rule does not use the model.
- Off until `TYPESAFE_API_KEY` is set. Questions and thresholds are YAML under `guard/data/`; thresholds can be overridden with `ASC_GUARD_*` variables. If Jev is unreachable, shell, network and MCP calls ask first.
- The plugin ships `hooks/hooks.json`; `asc-guard install` writes the same hooks into a settings file.

### Changed — one error shape for every tool
- Failures now return `{"success": false, "error": {"code", "message", "hint"}}`, with the same fields in every tool, so the agent can branch on `code` and follow `hint`. `error` used to be a plain string in some tools.
- Bad `packages_json` returns `invalid_json` or `invalid_packages` with an example of the expected input.
- `verify_packages` no longer reports a package as `package_not_found` when the registry could not be reached or the ecosystem is unsupported. Those come back as `registry_unavailable` or `unsupported_ecosystem`, which are not the same as invalid.
- `scan_dependencies` and `verify_packages` list per-package failures under `errors`.

### Changed — the agent judges reachability, not the server
- `scan_dependencies` no longer takes `code_snippets` and no longer decides reachability. The regex import and call matching, the keyword matching against advisory text, and the `ctx.sample()` call are removed. Each vulnerability now returns a `reachability_check` (affected symbols from OSV, or `no_symbol_data`, a question, and the fixed version) that the calling agent answers by reading its own code. Vulnerabilities also list `fixed_versions`. This keeps code out of tool calls and works with clients that do not support sampling

### Changed — code review no longer sends the code through the tool
- `verify_code_security` no longer needs the code. The checklist depends only on the components, so the `code` argument is now optional, deprecated, and ignored, and the response no longer repeats the code (it used to return it twice). The agent reviews the code already in its context against the returned checklist. This keeps large changes from being pasted into the tool call and echoed back

### Added — cryptography, transport security, and MCP Top 10 ids
- New components `cryptography` and `transport-security` with five threats (weak algorithms, hardcoded keys, weak random generators, cleartext transport, outdated TLS) and four countermeasures
- Threats can carry `mcp_top10` ids (OWASP MCP Top 10 2025); the agent, LLM, and MCP threats are tagged, and the review and threat-model tools return them. A test checks every cited id against the official list

### Changed — code review and threat modeling use the threat library
- `verify_code_security` takes `components`, `data_handled`, and `project_root` instead of `security_context`. Its focus areas and checklist come from the library's threats and countermeasures for the components you name, plus a short baseline. There is no language detection; the agent adapts each fix to its own stack
- `perform_threat_model` takes `components`, `data_handled`, and `project_root`, and returns `known_threats` (library threats and countermeasures, or the component menu) in place of `security_signals`
- Countermeasures can be marked `baseline: true` to always appear in code review checklists
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
