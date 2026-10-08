import asyncio
import logging
import os
import sys
from importlib.metadata import PackageNotFoundError, version

import click
from dotenv import load_dotenv

from mcp_security_review.utils.env import is_env_truthy
from mcp_security_review.utils.lifecycle import (
    ensure_clean_exit,
    setup_signal_handlers,
)
from mcp_security_review.utils.logging import setup_logging

try:
    __version__ = version("mcp-security-review")
except PackageNotFoundError:
    # package is not installed
    __version__ = "0.0.0"

# Initialize logging with appropriate level
logging_level = logging.WARNING
if is_env_truthy("MCP_VERBOSE"):
    logging_level = logging.DEBUG

# Set up logging to STDOUT if MCP_LOGGING_STDOUT is set to true
logging_stream = sys.stdout if is_env_truthy("MCP_LOGGING_STDOUT") else sys.stderr

# Set up logging using the utility function
logger = setup_logging(logging_level, logging_stream)


@click.version_option(__version__, prog_name="mcp-security-review")
@click.command()
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Increase verbosity (can be used multiple times)",
)
@click.option(
    "--env-file", type=click.Path(exists=True, dir_okay=False), help="Path to .env file"
)
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse", "streamable-http"]),
    default="stdio",
    help="Transport type (stdio, sse, or streamable-http)",
)
@click.option(
    "--port",
    default=8000,
    help="Port to listen on for SSE or Streamable HTTP transport",
)
@click.option(
    "--host",
    default="0.0.0.0",  # noqa: S104
    help="Host to bind to for SSE or Streamable HTTP transport (default: 0.0.0.0)",
)
@click.option(
    "--path",
    default="/mcp",
    help="Path for Streamable HTTP transport (e.g., /mcp).",
)
@click.option(
    "--read-only",
    is_flag=True,
    help="Run in read-only mode (disables all write operations)",
)
@click.option(
    "--enabled-tools",
    help="Comma-separated list of tools to enable (enables all if not specified)",
)
def main(
    verbose: int,
    env_file: str | None,
    transport: str,
    port: int,
    host: str,
    path: str | None,
    read_only: bool,
    enabled_tools: str | None,
) -> None:
    """MCP Security Review Server - Chill security reviews while vibe coding

    Perfect for staying in your coding flow while keeping security top of mind.
    Quickly assess risks, check dependencies, and model threats without breaking
    rhythm.
    """
    # Logging level logic
    if verbose == 1:
        current_logging_level = logging.INFO
    elif verbose >= 2:  # -vv or more
        current_logging_level = logging.DEBUG
    else:
        # Default to DEBUG if MCP_VERY_VERBOSE is set, else INFO if MCP_VERBOSE is set, else WARNING
        if is_env_truthy("MCP_VERY_VERBOSE", "false"):
            current_logging_level = logging.DEBUG
        elif is_env_truthy("MCP_VERBOSE", "false"):
            current_logging_level = logging.INFO
        else:
            current_logging_level = logging.WARNING

    # Set up logging to STDOUT if MCP_LOGGING_STDOUT is set to true
    logging_stream = sys.stdout if is_env_truthy("MCP_LOGGING_STDOUT") else sys.stderr

    global logger
    logger = setup_logging(current_logging_level, logging_stream)
    logger.debug(f"Logging level set to: {logging.getLevelName(current_logging_level)}")
    logger.debug(
        f"Logging stream set to: {'stdout' if logging_stream is sys.stdout else 'stderr'}"
    )

    def was_option_provided(ctx: click.Context, param_name: str) -> bool:
        return (
            ctx.get_parameter_source(param_name)
            != click.core.ParameterSource.DEFAULT_MAP
            and ctx.get_parameter_source(param_name)
            != click.core.ParameterSource.DEFAULT
        )

    if env_file:
        logger.debug(f"Loading environment from file: {env_file}")
        load_dotenv(env_file, override=True)
    else:
        logger.debug(
            "Attempting to load environment from default .env file if it exists"
        )
        load_dotenv(override=True)

    click_ctx = click.get_current_context(silent=True)

    # Transport precedence
    final_transport = os.getenv("TRANSPORT", "stdio").lower()
    if click_ctx and was_option_provided(click_ctx, "transport"):
        final_transport = transport
    if final_transport not in ["stdio", "sse", "streamable-http"]:
        logger.warning(
            f"Invalid transport '{final_transport}' from env/default, using 'stdio'."
        )
        final_transport = "stdio"
    logger.debug(f"Final transport determined: {final_transport}")

    # Port precedence
    final_port = 8000
    if os.getenv("PORT") and os.getenv("PORT").isdigit():
        final_port = int(os.getenv("PORT"))
    if click_ctx and was_option_provided(click_ctx, "port"):
        final_port = port
    logger.debug(f"Final port for HTTP transports: {final_port}")

    # Host precedence
    final_host = os.getenv("HOST", "0.0.0.0")  # noqa: S104
    if click_ctx and was_option_provided(click_ctx, "host"):
        final_host = host
    logger.debug(f"Final host for HTTP transports: {final_host}")

    # Path precedence
    final_path: str | None = os.getenv("STREAMABLE_HTTP_PATH", None)
    if click_ctx and was_option_provided(click_ctx, "path"):
        final_path = path
    logger.debug(
        f"Final path for Streamable HTTP: {final_path if final_path else 'FastMCP default'}"
    )

    # Set env vars for downstream config
    if click_ctx and was_option_provided(click_ctx, "enabled_tools"):
        os.environ["ENABLED_TOOLS"] = enabled_tools
    if click_ctx and was_option_provided(click_ctx, "read_only"):
        os.environ["READ_ONLY_MODE"] = str(read_only).lower()

    from mcp_security_review.servers import main_mcp

    run_kwargs = {
        "transport": final_transport,
    }

    if final_transport == "stdio":
        logger.info("Starting server with STDIO transport.")
    elif final_transport in ["sse", "streamable-http"]:
        run_kwargs["host"] = final_host
        run_kwargs["port"] = final_port
        run_kwargs["log_level"] = logging.getLevelName(current_logging_level).lower()

        if final_path is not None:
            run_kwargs["path"] = final_path

        log_display_path = final_path
        if log_display_path is None:
            if final_transport == "sse":
                log_display_path = main_mcp.settings.sse_path or "/sse"
            else:
                log_display_path = main_mcp.settings.streamable_http_path or "/mcp"

        logger.info(
            f"Starting server with {final_transport.upper()} transport on http://{final_host}:{final_port}{log_display_path}"
        )
    else:
        logger.error(
            f"Invalid transport type '{final_transport}' determined. Cannot start server."
        )
        sys.exit(1)

    # Set up signal handlers for graceful shutdown
    setup_signal_handlers()

    # For STDIO transport, also handle EOF detection
    if final_transport == "stdio":
        logger.debug("STDIO transport detected, setting up stdin monitoring")

    try:
        logger.debug("Starting asyncio event loop...")

        # For stdio transport, don't monitor stdin as MCP server handles it internally
        # This prevents race conditions where both try to read from the same stdin
        if final_transport == "stdio":
            asyncio.run(main_mcp.run_async(**run_kwargs))
        else:
            # For HTTP transports (SSE, streamable-http), don't use stdin monitoring
            # as it causes premature shutdown when the client closes stdin
            # The server should only rely on OS signals for shutdown
            logger.debug(
                f"Running server for {final_transport} transport without stdin monitoring"
            )
            asyncio.run(main_mcp.run_async(**run_kwargs))
    except (KeyboardInterrupt, SystemExit) as e:
        logger.info(f"Server shutdown initiated: {type(e).__name__}")
    except Exception as e:
        logger.error(f"Server encountered an error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        ensure_clean_exit()


__all__ = ["main", "__version__"]

if __name__ == "__main__":
    main()
