# AGENTS

> **Audience**: LLM-driven engineering agents

This file provides guidance for autonomous coding agents working inside the **AI Security Crew** repository.

---

## Repository map

| Path | Purpose |
| --- | --- |
| `src/mcp_security_review/` | Library source code (Python ≥ 3.10) |
| `  ├─ providers/sca/` | Package registry and OSV vulnerability providers |
| `  ├─ servers/` | FastMCP server implementations |
| `  ├─ library/` | Threat library: components, threats, countermeasures (YAML) |
| `  ├─ security/` | Code review context and threat modeling |
| `  └─ utils/` | Shared utilities (env, logging, lifecycle) |
| `tests/` | Pytest test suite with fixtures |
| `scripts/` | Guideline and assessment helper scripts |

---

## Security tool workflow

> **Note**: This workflow is also delivered to end users automatically via the MCP server's `instructions` field on connect. Changes here should stay in sync with `servers/main.py`.

### Before starting any coding task
- Call `general_lightweight_security_review` with the task description. It returns a menu of components. Call it again with `components` set to the ids this change adds or modifies (usually 2 to 5) (and `data_handled` for credentials, payments, or personal data) to get the threats and countermeasures.
- If the task comes from a ticket or page link (Jira, Confluence, Linear, GitHub issues, and so on), fetch it first with the matching MCP server you have connected and pass its details as the task description.
- For significant new features (auth, file handling, external integrations), also call `threatmodel_perform_threat_model`.

### When adding or updating packages
Run both steps before writing code that uses the new packages:

1. **Verify packages exist** — call `sca_verify_packages`. Fix any invalid packages before proceeding.
2. **Scan for vulnerabilities** — call `sca_scan_dependencies` in parallel with `general_verify_code_security`, passing the packages and code snippets where they are used. Act on results:
   - `reachable` or `uncertain` → upgrade or avoid the vulnerable function before continuing
   - `not_reachable` / `not_imported` → note it and continue; consider upgrading anyway

Both SCA tools accept a JSON array of `{"name", "version", "ecosystem"}` objects (`"pypi"` or `"npm"`).

### After generating code
- Call `general_verify_code_security` with the generated code. Follow the `review_prompt` in the response to perform the analysis and report findings.

### Persisting threat models
- After `threatmodel_perform_threat_model`, call `threatmodel_update_threat_model_file` to write `threat-model.md`.
- If earlier threat models exist in a wiki or docs tool you have connected, fetch them first and pass them as `previous_models_json` to avoid duplicating work.

---

## Mandatory dev workflow

```bash
uv sync --frozen --dev  # install dependencies
pre-commit install                    # setup hooks
pre-commit run --all-files           # Ruff + Prettier + Pyright
uv run pytest                        # run full test suite
```

*Tests must pass* and *lint/typing must be clean* before committing.

---

## Core MCP patterns

**Tool naming**: `{server}_{tool}` (e.g., `sca_verify_packages`); each sub-server is mounted in `servers/main.py`

**Architecture**:
- **Servers**: One FastMCP sub-server per area (`general`, `threatmodel`, `sca`), mounted in `servers/main.py`
- **Providers**: External lookups (OSV, PyPI, npm) live in `providers/`
- **Tickets and docs**: No Jira/Confluence code here; agents fetch tickets with whatever MCP server the user has connected

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
uv run mcp-security-review -v              # Verbose mode

# Git workflow
git checkout -b feature/description   # New feature
git checkout -b fix/issue-description # Bug fix
git commit --trailer "Reported-by:<name>"      # Attribution
git commit --trailer "Github-Issue:#<number>"  # Issue reference
```
