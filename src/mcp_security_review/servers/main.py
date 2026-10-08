"""Main MCP server: mounts the security tool servers and filters tools."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastmcp import FastMCP
from fastmcp.tools import Tool as FastMCPTool
from mcp.types import Tool as MCPTool
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_security_review.utils.io import is_read_only_mode
from mcp_security_review.utils.tools import get_enabled_tools, should_include_tool

from .context import MainAppContext
from .general import general_mcp
from .sca import sca_mcp
from .threat_model import threat_model_mcp

logger = logging.getLogger("mcp-security-review.server.main")


async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@asynccontextmanager
async def main_lifespan(app: FastMCP[MainAppContext]) -> AsyncIterator[dict[str, Any]]:
    logger.info("Main Security Review MCP server lifespan starting...")
    read_only = is_read_only_mode()
    enabled_tools = get_enabled_tools()

    app_context = MainAppContext(read_only=read_only, enabled_tools=enabled_tools)
    logger.info(f"Read-only mode: {'ENABLED' if read_only else 'DISABLED'}")
    logger.info(f"Enabled tools filter: {enabled_tools or 'All tools enabled'}")

    try:
        yield {"app_lifespan_context": app_context}
    finally:
        logger.info("Main Security Review MCP server lifespan shutdown complete.")


class SecurityReviewMCP(FastMCP[MainAppContext]):
    """Custom FastMCP server class for security review workflows with tool filtering."""

    async def _mcp_list_tools(self) -> list[MCPTool]:
        # Filter tools based on enabled_tools, read_only mode, and service config.
        req_context = self._mcp_server.request_context
        if req_context is None or req_context.lifespan_context is None:
            logger.warning(
                "Lifespan context not available during _main_mcp_list_tools call."
            )
            return []

        lifespan_ctx_dict = req_context.lifespan_context
        app_lifespan_state: MainAppContext | None = (
            lifespan_ctx_dict.get("app_lifespan_context")
            if isinstance(lifespan_ctx_dict, dict)
            else None
        )
        read_only = (
            getattr(app_lifespan_state, "read_only", False)
            if app_lifespan_state
            else False
        )
        enabled_tools_filter = (
            getattr(app_lifespan_state, "enabled_tools", None)
            if app_lifespan_state
            else None
        )
        logger.debug(
            f"_main_mcp_list_tools: read_only={read_only}, "
            f"enabled_tools_filter={enabled_tools_filter}"
        )

        all_tools: dict[str, FastMCPTool] = await self.get_tools()
        logger.debug(
            f"Aggregated {len(all_tools)} tools before filtering: "
            f"{list(all_tools.keys())}"
        )

        filtered_tools: list[MCPTool] = []
        for registered_name, tool_obj in all_tools.items():
            tool_tags = tool_obj.tags

            if not should_include_tool(registered_name, enabled_tools_filter):
                logger.debug(f"Excluding tool '{registered_name}' (not enabled)")
                continue

            if tool_obj and read_only and "write" in tool_tags:
                logger.debug(
                    f"Excluding tool '{registered_name}' due to read-only mode "
                    f"and 'write' tag"
                )
                continue

            filtered_tools.append(tool_obj.to_mcp_tool(name=registered_name))

        logger.debug(
            f"_main_mcp_list_tools: Total tools after filtering: {len(filtered_tools)}"
        )
        return filtered_tools


AGENT_INSTRUCTIONS = (
    "# Security Review MCP — Agent Workflow\n\n"
    "Follow this workflow whenever you write or modify code.\n\n"
    "## 1. Before you start coding\n"
    "Call `general_lightweight_security_review` with a description of what you're building and the tech stack.\n"  # noqa: E501
    "- Use this for any non-trivial coding task to identify risks and get security guidelines upfront.\n"  # noqa: E501
    "- If the task comes from a ticket or page link (Jira, Confluence, Linear, GitHub issues, Notion, and so on), fetch it first with the matching MCP server you have connected, then pass its summary, description, and acceptance criteria as the task description.\n"  # noqa: E501
    "- For significant new features (auth, file handling, external integrations), also call `threatmodel_perform_threat_model`.\n\n"  # noqa: E501
    "## 2. When adding or updating dependencies\n"
    "Run both steps before writing any code that uses the new packages:\n"
    "1. Call `sca_verify_packages` — confirms packages exist with valid versions. Fix any invalid packages before proceeding.\n"  # noqa: E501
    "2. Call `sca_scan_dependencies` in parallel with step 3 — scans for CVEs and checks reachability. Act on results:\n"  # noqa: E501
    "   - `reachable` or `uncertain` → upgrade or avoid the vulnerable function before continuing.\n"  # noqa: E501
    "   - `not_reachable` / `not_imported` → note it and continue; consider upgrading anyway.\n\n"  # noqa: E501
    "## 3. After generating code\n"
    "Call `general_verify_code_security` with the generated code.\n"
    "- Run this after every non-trivial code generation before presenting results to the user.\n"  # noqa: E501
    "- Follow the `review_prompt` in the response to perform the analysis and report findings.\n\n"  # noqa: E501
    "## 4. Persisting threat models (optional)\n"
    "After `threatmodel_perform_threat_model`, call `threatmodel_update_threat_model_file` to write `threat-model.md`.\n"  # noqa: E501
    "If earlier threat models or design pages exist in a wiki or docs tool you have connected, fetch them first and pass them as `previous_models_json` to avoid duplicating work.\n"  # noqa: E501
)

main_mcp = SecurityReviewMCP(
    name="Security Review MCP",
    lifespan=main_lifespan,
    instructions=AGENT_INSTRUCTIONS,
)
main_mcp.mount("general", general_mcp)
main_mcp.mount("threatmodel", threat_model_mcp)
main_mcp.mount("sca", sca_mcp)


@main_mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
async def _health_check_route(request: Request) -> JSONResponse:
    return await health_check(request)


logger.info("Added /healthz endpoint for Kubernetes probes")
