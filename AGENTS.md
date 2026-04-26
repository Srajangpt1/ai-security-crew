# AGENTS

> **Audience**: LLM-driven engineering agents

This file provides guidance for autonomous coding agents working inside the **AI Security Crew** repository.

---

## Repository map

| Path | Purpose |
| --- | --- |
| `src/mcp_security_review/` | Library source code (Python ≥ 3.10) |
| `  ├─ providers/atlassian/` | Atlassian service providers (Jira, Confluence) |
| `  ├─ models/atlassian/` | Pydantic data models for Atlassian APIs |
| `  ├─ servers/` | FastMCP server implementations |
| `  ├─ security/` | Security assessment and guidelines |
| `  └─ utils/` | Shared utilities (auth, logging, SSL) |
| `tests/` | Pytest test suite with fixtures |
| `scripts/` | OAuth setup and testing scripts |

---

## Security tool workflow

> **Note**: This workflow is also delivered to end users automatically via the MCP server's `instructions` field on connect. Changes here should stay in sync with `servers/main.py`.

### Before starting any coding task
- Call `lightweight_security_review` with the task description and tech stack.
- If working from a Jira ticket, call `assess_ticket_security` instead.
- For significant new features (auth, file handling, external integrations), also call `perform_threat_model`.

### When adding or updating packages
Run both steps before writing code that uses the new packages:

1. **Verify packages exist** — call `verify_packages`. Fix any invalid packages before proceeding.
2. **Scan for vulnerabilities** — call `scan_dependencies` in parallel with `verify_code_security`, passing the packages and code snippets where they are used. Act on results:
   - `reachable` or `uncertain` → upgrade or avoid the vulnerable function before continuing
   - `not_reachable` / `not_imported` → note it and continue; consider upgrading anyway

Both SCA tools accept a JSON array of `{"name", "version", "ecosystem"}` objects (`"pypi"` or `"npm"`).

### After generating code
- Call `verify_code_security` with the generated code. Follow the `review_prompt` in the response to perform the analysis and report findings.

### Persisting threat models
- After `perform_threat_model`, call `update_threat_model_file` to write `threat-model.md`.
- Call `search_previous_threat_models` first to avoid duplicating existing models.

---

## Mandatory dev workflow

```bash
uv sync --frozen --all-extras --dev  # install dependencies
pre-commit install                    # setup hooks
pre-commit run --all-files           # Ruff + Prettier + Pyright
uv run pytest                        # run full test suite
```

*Tests must pass* and *lint/typing must be clean* before committing.

---

## Claude Code Hook Setup

Automatically triggers a security review on every feature-building prompt — no manual `/sec-review` needed.

**Global install** (fires in every project — recommended for personal machines):

```bash
python3 scripts/setup_claude_hook.py           # default, same as --global
python3 scripts/setup_claude_hook.py --global  # explicit
```

**Project-scoped install** (fires only when working inside this repo):

```bash
python3 scripts/setup_claude_hook.py --project
```

Then restart Claude Code.

The hook detects intent, checks if the MCP server is running, and routes to the appropriate security review:
- **MCP running** → instructs Claude to call `lightweight_security_review` (full integration)
- **MCP not running** → runs `SecurityAssessment` standalone (150+ OWASP guidelines)
- **Neither available** → injects inline OWASP reminders + setup guidance

**How global install works:** the setup script creates a stable symlink at `~/.claude/hooks/security_hook.py` and registers that path in `~/.claude/settings.json`. If you move the repo, re-run the setup script — only the symlink updates, `settings.json` stays unchanged.

**Project-scoped note:** `.claude/settings.json` is gitignored, so each developer must run the setup script once after cloning.

---

## Core MCP patterns

**Tool naming**: `{provider}_{service}_{action}` (e.g., `atlassian_jira_create_issue`)

**Architecture**:
- **Mixins**: Functionality split into focused mixins extending base clients
- **Models**: All data structures extend `ApiModel` base class
- **Auth**: Supports API tokens, PAT tokens, and OAuth 2.0

---

## Development rules

1. **Package management**: ONLY use `uv`, NEVER `pip`
2. **Branching**: NEVER work on `main`, always create feature branches
3. **Type safety**: All functions require type hints
4. **Testing**: New features need tests, bug fixes need regression tests
5. **Commits**: Use trailers for attribution, never mention tools/AI

---

## Code conventions

* **Language**: Python ≥ 3.10
* **Line length**: 88 characters maximum
* **Imports**: Absolute imports, sorted by ruff
* **Naming**: `snake_case` functions, `PascalCase` classes
* **Docstrings**: Google-style for all public APIs
* **Error handling**: Specific exceptions only

---

## Development guidelines

1. Do what has been asked; nothing more, nothing less
2. NEVER create files unless absolutely necessary
3. Always prefer editing existing files
4. Follow established patterns and maintain consistency
5. Run `pre-commit run --all-files` before committing
6. Fix bugs immediately when reported

---

## Quick reference

```bash
# Running the server
uv run mcp-security-review                 # Start server
uv run mcp-security-review --oauth-setup   # OAuth wizard
uv run mcp-security-review -v              # Verbose mode

# Git workflow
git checkout -b feature/description   # New feature
git checkout -b fix/issue-description # Bug fix
git commit --trailer "Reported-by:<name>"      # Attribution
git commit --trailer "Github-Issue:#<number>"  # Issue reference
```
