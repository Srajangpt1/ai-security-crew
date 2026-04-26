"""Unit tests for the Claude Code UserPromptSubmit security hook.

Tests cover detection logic (trigger / skip / false positive) using the
bash hook script directly via subprocess, and the Python runner via its
public interface.
"""

import json
import subprocess
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
HOOK_SCRIPT = SCRIPTS_DIR / "security_hook.sh"


def run_hook(prompt: str) -> tuple[str, int]:
    """Run security_hook.sh with a prompt and return (stdout, returncode)."""
    result = subprocess.run(
        ["bash", str(HOOK_SCRIPT)],
        input=json.dumps({"prompt": prompt}),
        capture_output=True,
        text=True,
    )
    return result.stdout.strip(), result.returncode


class TestDetectionSkips:
    """Prompts that should NOT trigger the security hook."""

    def test_short_prompt_skipped(self) -> None:
        output, code = run_hook("add it")
        assert output == ""
        assert code == 0

    def test_informational_prompt_skipped(self) -> None:
        output, code = run_hook("explain how JWT authentication works in detail please")
        assert output == ""
        assert code == 0

    def test_how_does_prompt_skipped(self) -> None:
        output, code = run_hook("how does OAuth2 token refresh work in practice")
        assert output == ""
        assert code == 0

    def test_review_prompt_skipped(self) -> None:
        output, code = run_hook("review the authentication code in auth.py for me")
        assert output == ""
        assert code == 0

    def test_refactor_prompt_skipped(self) -> None:
        output, code = run_hook("refactor the login function to make it cleaner")
        assert output == ""
        assert code == 0

    def test_docs_prompt_skipped(self) -> None:
        output, code = run_hook(
            "write documentation for the authentication module please"
        )
        assert output == ""
        assert code == 0

    def test_add_comment_false_positive_skipped(self) -> None:
        output, code = run_hook("add a comment to explain this function here")
        assert output == ""
        assert code == 0

    def test_security_review_prompt_skipped(self) -> None:
        # "review" keyword catches this before the action-verb check
        output, code = run_hook(
            "implement a security review process for the login flow"
        )
        assert output == ""
        assert code == 0

    def test_action_keyword_without_tech_term_and_short_skipped(self) -> None:
        output, code = run_hook("make it work better now")
        assert output == ""
        assert code == 0


class TestDetectionTriggers:
    """Prompts that SHOULD trigger the security hook."""

    def test_implement_jwt_login_triggers(self) -> None:
        output, code = run_hook("implement user login with JWT and session management")
        assert output != ""
        assert code == 0
        assert "SECURITY" in output

    def test_create_payment_service_triggers(self) -> None:
        output, code = run_hook("create a payment service integration with Stripe")
        assert output != ""
        assert "SECURITY" in output

    def test_add_api_endpoint_triggers(self) -> None:
        output, code = run_hook("add a REST API endpoint for user registration")
        assert output != ""
        assert "SECURITY" in output

    def test_build_auth_system_triggers(self) -> None:
        output, code = run_hook(
            "build an authentication system using OAuth2 for the app"
        )
        assert output != ""
        assert "SECURITY" in output

    def test_develop_upload_feature_triggers(self) -> None:
        output, code = run_hook("develop a file upload feature for the backend service")
        assert output != ""
        assert "SECURITY" in output

    def test_long_prompt_without_tech_term_triggers(self) -> None:
        output, code = run_hook(
            "build a system that allows users to sign in and manage "
            "their account preferences and settings across the platform"
        )
        assert output != ""
        assert "SECURITY" in output

    def test_integrate_webhook_triggers(self) -> None:
        output, code = run_hook(
            "integrate a webhook handler for incoming payment events"
        )
        assert output != ""
        assert "SECURITY" in output

    def test_write_database_migration_triggers(self) -> None:
        output, code = run_hook(
            "write a database migration to add the user tokens table"
        )
        assert output != ""
        assert "SECURITY" in output

    def test_build_security_module_triggers(self) -> None:
        # Previously a false negative — "security" keyword caused early exit
        output, code = run_hook("build a security module for my API")
        assert output != ""
        assert "SECURITY" in output

    def test_add_security_headers_triggers(self) -> None:
        # Previously a false negative — "security" keyword caused early exit
        output, code = run_hook("add security headers to the authentication service")
        assert output != ""
        assert "SECURITY" in output


class TestHookOutputFormat:
    """Hook output always contains expected structure."""

    def test_output_contains_warning_header(self) -> None:
        output, _ = run_hook("implement user login with JWT and session management")
        assert "AI SECURITY CREW" in output

    def test_exit_code_always_zero(self) -> None:
        """Hook must never block Claude — always exits 0."""
        _, code = run_hook("implement user login with JWT and session management")
        assert code == 0

    def test_skip_exit_code_zero(self) -> None:
        _, code = run_hook("explain JWT")
        assert code == 0

    def test_malformed_json_input_handled(self) -> None:
        result = subprocess.run(
            ["bash", str(HOOK_SCRIPT)],
            input="not valid json",
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
