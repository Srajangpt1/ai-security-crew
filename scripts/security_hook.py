#!/usr/bin/env python3
"""Claude Code UserPromptSubmit hook.

Detects feature-building intent and routes to:
- MCP tool (if Docker image is available)
- Python SecurityAssessment standalone (if uv is available)
- Inline OWASP reminders (fallback)
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_DIR = Path(__file__).parent.parent

_SKIP_RE = re.compile(
    r"\b(explain|what is|how does|show me|why|review|document|"
    r"documentation|docs|comment|refactor|rename|format|lint|clean)\b"
)
_ACTION_RE = re.compile(
    r"\b(build|implement|create|add|develop|integrate|write|make|scaffold|set up)\b"
)
_TECH_RE = re.compile(
    r"\b(api|endpoint|route|auth|authentication|database|service|component|"
    r"function|module|integration|jwt|oauth|login|upload|payment|user|token|"
    r"cache|queue|webhook|feature|flow|system|backend|frontend)\b"
)


def _read_prompt() -> str:
    raw = sys.stdin.read()
    try:
        return json.loads(raw).get("prompt", "")
    except (json.JSONDecodeError, AttributeError):
        return ""


def _should_skip(prompt: str) -> bool:
    lower = prompt.lower()
    if len(lower.split()) < 6:
        return True
    if _SKIP_RE.search(lower):
        return True
    if not _ACTION_RE.search(lower):
        return True
    if not _TECH_RE.search(lower) and len(lower.split()) <= 15:
        return True
    return False


def _route(prompt: str) -> None:
    # State 1: MCP Docker image available
    docker_bin = shutil.which("docker")
    if docker_bin:
        result = subprocess.run(  # noqa: S603
            [docker_bin, "image", "inspect", "mcp-security-review:latest"],
            capture_output=True,
        )
        if result.returncode == 0:
            print("⚠️  AI SECURITY CREW — SECURITY REVIEW REQUIRED ⚠️\n")
            print(
                "A feature-building task was detected. You MUST call the"
                " lightweight_security_review MCP tool before writing any code.\n"
            )
            print("Tool: lightweight_security_review")
            print(f"Task: {prompt}\n")
            print(
                "Apply ALL returned security requirements, guidelines, and checklist"
                " items to every line of code you generate."
                " Do not skip this step. Do not write code first."
            )
            return

    # State 2: uv available — run standalone Python runner
    uv_bin = shutil.which("uv")
    if uv_bin:
        try:
            result = subprocess.run(  # noqa: S603
                [uv_bin, "run", "python", "scripts/security_hook_runner.py"],
                input=prompt,
                capture_output=True,
                text=True,
                cwd=REPO_DIR,
            )
            if result.returncode == 0 and result.stdout.strip():
                print("\n⚠️  AI SECURITY CREW — SECURITY REVIEW (Standalone Mode) ⚠️\n")
                print(result.stdout)
                print(
                    "\nℹ️  MCP server not detected."
                    " For full integration (Jira, Confluence, CVE scanning):"
                )
                print(
                    f"   cd {REPO_DIR} && docker build -t mcp-security-review:latest ."
                )
                return
        except OSError:
            pass

    # State 3: Inline OWASP reminders
    print("⚠️  AI SECURITY CREW — SECURITY REMINDER ⚠️\n")
    print(
        "A feature-building task was detected."
        " Apply these principles to all generated code:\n"
    )
    print("- Validate and sanitize ALL user input server-side")
    print("- Use parameterized queries — never string-concatenate SQL")
    print("- Hash passwords with bcrypt or argon2 (never MD5/SHA1)")
    print("- Never hardcode secrets — use environment variables")
    print(
        "- Apply authentication and authorization checks on every sensitive operation"
    )
    print("- Return generic error messages — never expose stack traces")
    print("- Use HTTPS, set HttpOnly + SameSite cookies for session tokens\n")
    print("ℹ️  For full automated security reviews, set up AI Security Crew:")
    print(f"   cd {REPO_DIR} && uv sync && python3 scripts/setup_claude_hook.py")


def main() -> None:
    prompt = _read_prompt()
    if not prompt or _should_skip(prompt):
        sys.exit(0)
    _route(prompt)
    sys.exit(0)


if __name__ == "__main__":
    main()
