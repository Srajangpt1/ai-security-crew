#!/bin/bash
# Fires on every Claude Code UserPromptSubmit event.
# Detects feature-building intent and routes to MCP (primary),
# Python SecurityAssessment (fallback), or inline OWASP reminders.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

INPUT=$(cat)
PROMPT=$(echo "$INPUT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('prompt',''))" 2>/dev/null || echo "")
PROMPT_LOWER=$(echo "$PROMPT" | tr '[:upper:]' '[:lower:]')
WORD_COUNT=$(echo "$PROMPT" | wc -w | tr -d ' ')

# --- Detection (use if/fi to avoid set -e conflicts with grep exit codes) ---

if [ "$WORD_COUNT" -lt 6 ]; then exit 0; fi

if echo "$PROMPT_LOWER" | grep -qE "\b(explain|what is|how does|show me|why|review|document|documentation|docs|comment|refactor|rename|format|lint|clean)\b"; then exit 0; fi

if ! echo "$PROMPT_LOWER" | grep -qE "\b(build|implement|create|add|develop|integrate|write|make|scaffold|set up)\b"; then exit 0; fi

HAS_TECH=$(echo "$PROMPT_LOWER" | grep -cE "\b(api|endpoint|route|auth|authentication|database|service|component|function|module|integration|jwt|oauth|login|upload|payment|user|token|cache|queue|webhook|feature|flow|system|backend|frontend)\b" || true)
if [ "$HAS_TECH" -eq 0 ] && [ "$WORD_COUNT" -le 15 ]; then exit 0; fi

# --- Routing ---

# State 1: MCP image available — instruct Claude to call MCP tool
# Checks image existence, not running container (stdio MCP starts on-demand)
if command -v docker >/dev/null 2>&1 && docker image inspect mcp-security-review:latest >/dev/null 2>&1; then
  cat <<'EOF'
⚠️  AI SECURITY CREW — SECURITY REVIEW REQUIRED ⚠️

A feature-building task was detected. You MUST call the lightweight_security_review
MCP tool before writing any code.

Tool: lightweight_security_review
EOF
  printf 'Task: %s\n\n' "$PROMPT"
  cat <<'EOF'
Apply ALL returned security requirements, guidelines, and checklist items to every
line of code you generate. Do not skip this step. Do not write code first.
EOF
  exit 0
fi

# State 2: MCP image not found — try Python SecurityAssessment standalone (single uv run)
if command -v uv >/dev/null 2>&1; then
  if REVIEW_OUTPUT=$(printf '%s' "$PROMPT" | (cd "$REPO_DIR" && uv run python scripts/security_hook_runner.py) 2>/dev/null); then
    printf '\n⚠️  AI SECURITY CREW — SECURITY REVIEW (Standalone Mode) ⚠️\n\n'
    printf '%s\n' "$REVIEW_OUTPUT"
    printf '\nℹ️  MCP server not detected. For full integration (Jira, Confluence, CVE scanning):\n'
    printf '   cd %s && docker build -t mcp-security-review:latest .\n' "$REPO_DIR"
    exit 0
  fi
fi

# State 3: Nothing available — inline OWASP reminders + setup guidance
cat <<'EOF'
⚠️  AI SECURITY CREW — SECURITY REMINDER ⚠️

A feature-building task was detected. Apply these principles to all generated code:

- Validate and sanitize ALL user input server-side
- Use parameterized queries — never string-concatenate SQL
- Hash passwords with bcrypt or argon2 (never MD5/SHA1)
- Never hardcode secrets — use environment variables
- Apply authentication and authorization checks on every sensitive operation
- Return generic error messages — never expose stack traces
- Use HTTPS, set HttpOnly + SameSite cookies for session tokens

EOF
printf 'ℹ️  For full automated security reviews, set up AI Security Crew:\n'
printf '   cd %s && uv sync && bash scripts/setup_claude_hook.sh\n' "$REPO_DIR"
