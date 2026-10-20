"""Unit tests for transport selection and execution.

These tests verify that:
1. All transports use direct execution (no stdin monitoring)
2. Transport selection logic works correctly (CLI vs environment)
3. Error handling is preserved
"""

import json
import tomllib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from mcp_security_review import main

PYPROJECT = tomllib.loads(Path("pyproject.toml").read_text())


class TestMainTransportSelection:
    """Test the main function's transport-specific execution logic."""

    @pytest.fixture
    def mock_server(self):
        """Create a mock server instance."""
        server = MagicMock()
        server.run_async = AsyncMock(return_value=None)
        return server

    @pytest.fixture
    def mock_asyncio_run(self):
        """Mock asyncio.run to capture what coroutine is executed."""
        with patch("asyncio.run") as mock_run:
            # Store the coroutine for inspection
            mock_run.side_effect = lambda coro: setattr(mock_run, "_called_with", coro)
            yield mock_run

    @pytest.mark.parametrize("transport", ["stdio", "sse", "streamable-http"])
    def test_all_transports_use_direct_execution(
        self, mock_server, mock_asyncio_run, transport
    ):
        """Verify all transports use direct execution without stdin monitoring.

        This is a regression test for issues #519 and #524.
        """
        with patch(
            "mcp_security_review.servers.main.SecurityReviewMCP",
            return_value=mock_server,
        ):
            with patch.dict("os.environ", {"TRANSPORT": transport}):
                with patch("sys.argv", ["mcp-security-review"]):
                    try:
                        main()
                    except SystemExit:
                        pass

                    # Verify asyncio.run was called
                    assert mock_asyncio_run.called

                    # Get the coroutine info
                    called_coro = mock_asyncio_run._called_with
                    coro_repr = repr(called_coro)

                    # All transports must use direct execution
                    assert "run_with_stdio_monitoring" not in coro_repr
                    assert "run_async" in coro_repr or hasattr(called_coro, "cr_code")

    def test_cli_overrides_env_transport(self, mock_server, mock_asyncio_run):
        """Test that CLI transport argument overrides environment variable."""
        with patch(
            "mcp_security_review.servers.main.SecurityReviewMCP",
            return_value=mock_server,
        ):
            with patch.dict("os.environ", {"TRANSPORT": "sse"}):
                # Simulate CLI args with --transport stdio
                with patch("sys.argv", ["mcp-security-review", "--transport", "stdio"]):
                    try:
                        main()
                    except SystemExit:
                        pass

                    # All transports now use direct execution
                    called_coro = mock_asyncio_run._called_with
                    coro_repr = repr(called_coro)
                    assert "run_async" in coro_repr or hasattr(called_coro, "cr_code")

    def test_signal_handlers_always_setup(self, mock_server):
        """Test that signal handlers are set up regardless of transport."""
        with patch(
            "mcp_security_review.servers.main.SecurityReviewMCP",
            return_value=mock_server,
        ):
            with patch("asyncio.run"):
                # Patch where it's imported in the main module
                with patch("mcp_security_review.setup_signal_handlers") as mock_setup:
                    with patch.dict("os.environ", {"TRANSPORT": "stdio"}):
                        with patch("sys.argv", ["mcp-security-review"]):
                            try:
                                main()
                            except SystemExit:
                                pass

                            # Signal handlers should always be set up
                            mock_setup.assert_called_once()

    def test_error_handling_preserved(self, mock_server):
        """Test that error handling works correctly for all transports."""
        # Make the server's run_async raise an exception when awaited
        error = RuntimeError("Server error")

        async def failing_run_async(**kwargs):
            raise error

        mock_server.run_async = failing_run_async

        with patch(
            "mcp_security_review.servers.main.SecurityReviewMCP",
            return_value=mock_server,
        ):
            with patch("asyncio.run") as mock_run:
                # Simulate the exception propagating through asyncio.run
                mock_run.side_effect = error

                with patch.dict("os.environ", {"TRANSPORT": "stdio"}):
                    with patch("sys.argv", ["mcp-security-review"]):
                        # The main function logs the error and exits with code 1
                        with patch("sys.exit") as mock_exit:
                            main()
                            # Verify error was handled - sys.exit called with 1 for error
                            # and then with 0 in the finally block
                            assert mock_exit.call_count == 2
                            assert mock_exit.call_args_list[0][0][0] == 1  # Error exit
                            assert (
                                mock_exit.call_args_list[1][0][0] == 0
                            )  # Finally exit


def test_python_floor_is_311() -> None:
    """Project must require Python 3.11 at minimum, matching ruff's target."""
    assert PYPROJECT["project"]["requires-python"] == ">=3.11"
    assert PYPROJECT["tool"]["ruff"]["target-version"] == "py311"


def test_runtime_deps_present() -> None:
    """New intel-provider runtime dependencies must be declared."""
    deps = " ".join(PYPROJECT["project"]["dependencies"])
    for name in ("mitreattack-python", "cvss", "pillow>=12.3.0", "requests>=2.33.0"):
        assert name in deps


def test_live_marker_registered_and_deselected() -> None:
    """The 'live' pytest marker must be registered and off by default."""
    ini = PYPROJECT["tool"]["pytest"]["ini_options"]
    assert any(m.startswith("live:") for m in ini["markers"])
    assert "-m 'not live'" in ini["addopts"] or '-m "not live"' in ini["addopts"]


class TestFetchIntelCommand:
    """Tests for the `fetch-intel` subcommand and the bare command path."""

    def test_bare_command_still_starts_server(self) -> None:
        """With no subcommand, `main` must still start the server via stdio."""
        from mcp_security_review.servers.main import main_mcp

        mock_run_async = AsyncMock(return_value=None)
        with patch.object(main_mcp, "run_async", mock_run_async):
            with patch.dict("os.environ", {"TRANSPORT": "stdio"}):
                runner = CliRunner()
                result = runner.invoke(main, [])

        assert result.exit_code == 0
        mock_run_async.assert_called_once_with(transport="stdio")

    def test_fetch_intel_reports_each_source(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A clean cache refetches every source and prints its status."""
        monkeypatch.setenv("MCP_SECURITY_REVIEW_CACHE_DIR", str(tmp_path / "cache"))

        async def fake_fetch_intel(
            cache=None, *, sources=("kev", "ctid", "attack"), force=False
        ):
            return dict.fromkeys(sources, "ok")

        with patch("mcp_security_review.providers.intel.fetch_intel", fake_fetch_intel):
            runner = CliRunner()
            result = runner.invoke(main, ["fetch-intel"])

        assert result.exit_code == 0
        assert "kev: ok" in result.output
        assert "ctid: ok" in result.output
        assert "attack: ok" in result.output

    def test_fetch_intel_partial_failure_exit_zero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One source failing must still exit 0 and report the failure."""
        from mcp_security_review.providers import attack, intel

        monkeypatch.setenv("MCP_SECURITY_REVIEW_CACHE_DIR", str(tmp_path / "cache"))

        async def ok(*_args, **_kwargs):
            return {}

        async def boom(*_args, **_kwargs):
            raise intel.FetchError("timeout")

        monkeypatch.setattr(intel, "load_kev", ok)
        monkeypatch.setattr(intel, "load_ctid", ok)
        monkeypatch.setattr(attack, "refresh_attack_index", boom)

        runner = CliRunner()
        result = runner.invoke(main, ["fetch-intel"])

        assert result.exit_code == 0
        assert "attack: failed: timeout" in result.output

    def test_quiet_suppresses_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--quiet must suppress the per-source status lines."""
        monkeypatch.setenv("MCP_SECURITY_REVIEW_CACHE_DIR", str(tmp_path / "cache"))

        async def fake_fetch_intel(
            cache=None, *, sources=("kev", "ctid", "attack"), force=False
        ):
            return dict.fromkeys(sources, "ok")

        with patch("mcp_security_review.providers.intel.fetch_intel", fake_fetch_intel):
            runner = CliRunner()
            result = runner.invoke(main, ["fetch-intel", "--quiet"])

        assert result.exit_code == 0
        assert result.output == ""

    def test_force_flag_is_passed_through(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--force must reach `fetch_intel` as `force=True`."""
        monkeypatch.setenv("MCP_SECURITY_REVIEW_CACHE_DIR", str(tmp_path / "cache"))
        received_force: list[bool] = []

        async def fake_fetch_intel(
            cache=None, *, sources=("kev", "ctid", "attack"), force=False
        ):
            received_force.append(force)
            return {}

        with patch("mcp_security_review.providers.intel.fetch_intel", fake_fetch_intel):
            runner = CliRunner()
            result = runner.invoke(main, ["fetch-intel", "--force"])

        assert result.exit_code == 0
        assert received_force == [True]


def test_hook_json_has_background_prefetch_with_opt_out() -> None:
    """The SessionStart hook runs fetch-intel in the background, with an opt-out."""
    hooks = json.loads(Path("hooks/hooks.json").read_text())

    assert "PreToolUse" in hooks["hooks"]
    assert "PostToolUse" in hooks["hooks"]
    assert "UserPromptSubmit" in hooks["hooks"]

    session_start = hooks["hooks"]["SessionStart"]
    command = session_start[0]["hooks"][0]["command"]
    assert "MCP_SECURITY_REVIEW_NO_PREFETCH" in command
    assert "&" in command
    assert "exit 0" in command
    assert "fetch-intel --quiet" in command
