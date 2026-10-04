"""Main FastMCP server setup for security review workflows."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Literal, Optional

from cachetools import TTLCache
from fastmcp import FastMCP
from fastmcp.tools import Tool as FastMCPTool
from mcp.types import Tool as MCPTool
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_security_review.providers.atlassian.confluence import ConfluenceFetcher
from mcp_security_review.providers.atlassian.confluence.config import ConfluenceConfig
from mcp_security_review.providers.atlassian.jira import JiraFetcher
from mcp_security_review.providers.atlassian.jira.config import JiraConfig
from mcp_security_review.utils.environment import get_available_services
from mcp_security_review.utils.io import is_read_only_mode
from mcp_security_review.utils.logging import mask_sensitive
from mcp_security_review.utils.tools import get_enabled_tools, should_include_tool

from .confluence import confluence_mcp
from .context import MainAppContext
from .general import general_mcp
from .jira import jira_mcp
from .sca import sca_mcp
from .threat_model import threat_model_mcp

logger = logging.getLogger("mcp-security-review.server.main")


async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@asynccontextmanager
async def main_lifespan(app: FastMCP[MainAppContext]) -> AsyncIterator[dict]:
    logger.info("Main Security Review MCP server lifespan starting...")
    services = get_available_services()
    read_only = is_read_only_mode()
    enabled_tools = get_enabled_tools()

    loaded_jira_config: JiraConfig | None = None
    loaded_confluence_config: ConfluenceConfig | None = None

    if services.get("jira"):
        try:
            jira_config = JiraConfig.from_env()
            if jira_config.is_auth_configured():
                loaded_jira_config = jira_config
                logger.info(
                    "Jira configuration loaded and authentication is configured."
                )
            else:
                logger.warning(
                    "Jira URL found, but authentication is not fully configured. "
                    "Jira tools will be unavailable."
                )
        except Exception as e:
            logger.error(f"Failed to load Jira configuration: {e}", exc_info=True)

    if services.get("confluence"):
        try:
            confluence_config = ConfluenceConfig.from_env()
            if confluence_config.is_auth_configured():
                loaded_confluence_config = confluence_config
                logger.info(
                    "Confluence configuration loaded and authentication is configured."
                )
            else:
                logger.warning(
                    "Confluence URL found, but authentication is not fully configured. "
                    "Confluence tools will be unavailable."
                )
        except Exception as e:
            logger.error(f"Failed to load Confluence configuration: {e}", exc_info=True)

    app_context = MainAppContext(
        full_jira_config=loaded_jira_config,
        full_confluence_config=loaded_confluence_config,
        read_only=read_only,
        enabled_tools=enabled_tools,
    )
    logger.info(f"Read-only mode: {'ENABLED' if read_only else 'DISABLED'}")
    logger.info(f"Enabled tools filter: {enabled_tools or 'All tools enabled'}")

    try:
        yield {"app_lifespan_context": app_context}
    except Exception as e:
        logger.error(f"Error during lifespan: {e}", exc_info=True)
        raise
    finally:
        logger.info("Main Atlassian MCP server lifespan shutting down...")
        # Perform any necessary cleanup here
        try:
            # Close any open connections if needed
            if loaded_jira_config:
                logger.debug("Cleaning up Jira resources...")
            if loaded_confluence_config:
                logger.debug("Cleaning up Confluence resources...")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}", exc_info=True)
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

            # Exclude Jira/Confluence tools if config is not fully authenticated
            is_jira_tool = "jira" in tool_tags
            is_confluence_tool = "confluence" in tool_tags
            service_configured_and_available = True
            if app_lifespan_state:
                if is_jira_tool and not app_lifespan_state.full_jira_config:
                    logger.debug(
                        f"Excluding Jira tool '{registered_name}': "
                        f"configuration/authentication is incomplete."
                    )
                    service_configured_and_available = False
                if is_confluence_tool and not app_lifespan_state.full_confluence_config:
                    logger.debug(
                        f"Excluding Confluence tool '{registered_name}': "
                        f"configuration/authentication is incomplete."
                    )
                    service_configured_and_available = False
            elif is_jira_tool or is_confluence_tool:
                logger.warning(
                    f"Excluding tool '{registered_name}': application context "
                    f"unavailable to verify service configuration."
                )
                service_configured_and_available = False

            if not service_configured_and_available:
                continue

            filtered_tools.append(tool_obj.to_mcp_tool(name=registered_name))

        logger.debug(
            f"_main_mcp_list_tools: Total tools after filtering: {len(filtered_tools)}"
        )
        return filtered_tools

    def http_app(
        self,
        path: str | None = None,
        middleware: list[Middleware] | None = None,
        transport: Literal["streamable-http", "sse"] = "streamable-http",
    ) -> "Starlette":
        user_token_mw = Middleware(UserTokenMiddleware, mcp_server_ref=self)
        final_middleware_list = [user_token_mw]
        if middleware:
            final_middleware_list.extend(middleware)
        app = super().http_app(
            path=path, middleware=final_middleware_list, transport=transport
        )
        return app


token_validation_cache: TTLCache[  # type: ignore[type-arg]
    int, tuple[bool, str | None, JiraFetcher | None, ConfluenceFetcher | None]
] = TTLCache(maxsize=100, ttl=300)


class UserTokenMiddleware(BaseHTTPMiddleware):
    """Middleware to extract Atlassian user tokens from Authorization headers."""

    def __init__(
        self, app: Any, mcp_server_ref: Optional["SecurityReviewMCP"] = None
    ) -> None:
        super().__init__(app)
        self.mcp_server_ref = mcp_server_ref
        if not self.mcp_server_ref:
            logger.warning(
                "UserTokenMiddleware initialized without mcp_server_ref. "
                "Path matching for MCP endpoint might fail if settings are needed."
            )

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> JSONResponse:
        logger.debug(
            f"UserTokenMiddleware.dispatch: ENTERED for request "
            f"path='{request.url.path}', method='{request.method}'"
        )
        mcp_server_instance = self.mcp_server_ref
        if mcp_server_instance is None:
            logger.debug(
                "UserTokenMiddleware.dispatch: self.mcp_server_ref is None. "
                "Skipping MCP auth logic."
            )
            return await call_next(request)

        mcp_path = mcp_server_instance.settings.streamable_http_path.rstrip("/")
        request_path = request.url.path.rstrip("/")
        logger.debug(
            f"UserTokenMiddleware.dispatch: Comparing request_path='{request_path}' "
            f"with mcp_path='{mcp_path}'. Request method='{request.method}'"
        )
        if request_path == mcp_path and request.method == "POST":
            auth_header = request.headers.get("Authorization")
            cloud_id_header = request.headers.get("X-Atlassian-Cloud-Id")

            token_for_log = mask_sensitive(
                auth_header.split(" ", 1)[1].strip()
                if auth_header and " " in auth_header
                else auth_header
            )
            logger.debug(
                f"UserTokenMiddleware: Path='{request.url.path}', "
                f"AuthHeader='{mask_sensitive(auth_header)}', "
                f"ParsedToken(masked)='{token_for_log}', "
                f"CloudId='{cloud_id_header}'"
            )

            # Extract and save cloudId if provided
            if cloud_id_header and cloud_id_header.strip():
                request.state.user_atlassian_cloud_id = cloud_id_header.strip()
                logger.debug(
                    f"UserTokenMiddleware: Extracted cloudId from header: "
                    f"{cloud_id_header.strip()}"
                )
            else:
                request.state.user_atlassian_cloud_id = None
                logger.debug(
                    "UserTokenMiddleware: No cloudId header provided, "
                    "will use global config"
                )

            # Check for mcp-session-id header for debugging
            mcp_session_id = request.headers.get("mcp-session-id")
            if mcp_session_id:
                logger.debug(
                    f"UserTokenMiddleware: MCP-Session-ID header found: "
                    f"{mcp_session_id}"
                )
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1].strip()
                if not token:
                    return JSONResponse(
                        {"error": "Unauthorized: Empty Bearer token"},
                        status_code=401,
                    )
                logger.debug(
                    f"UserTokenMiddleware.dispatch: Bearer token extracted "
                    f"(masked): ...{mask_sensitive(token, 8)}"
                )
                request.state.user_atlassian_token = token
                request.state.user_atlassian_auth_type = "oauth"
                request.state.user_atlassian_email = None
                logger.debug(
                    "UserTokenMiddleware.dispatch: Set request.state "
                    f"(pre-validation): auth_type='"
                    f"{getattr(request.state, 'user_atlassian_auth_type', 'N/A')}', "
                    f"token_present="
                    f"{bool(getattr(request.state, 'user_atlassian_token', None))}"
                )
            elif auth_header and auth_header.startswith("Token "):
                token = auth_header.split(" ", 1)[1].strip()
                if not token:
                    return JSONResponse(
                        {"error": "Unauthorized: Empty Token (PAT)"},
                        status_code=401,
                    )
                logger.debug(
                    f"UserTokenMiddleware.dispatch: PAT (Token scheme) extracted "
                    f"(masked): ...{mask_sensitive(token, 8)}"
                )
                request.state.user_atlassian_token = token
                request.state.user_atlassian_auth_type = "pat"
                request.state.user_atlassian_email = (
                    None  # PATs don't carry email in the token itself
                )
                logger.debug(
                    "UserTokenMiddleware.dispatch: Set request.state for PAT auth."
                )
            elif auth_header:
                auth_type = (
                    auth_header.split(" ", 1)[0]
                    if " " in auth_header
                    else "UnknownType"
                )
                logger.warning(
                    f"Unsupported Authorization type for "
                    f"{request.url.path}: {auth_type}"
                )
                return JSONResponse(
                    {
                        "error": (
                            "Unauthorized: Only 'Bearer <OAuthToken>' or "
                            "'Token <PAT>' types are supported."
                        )
                    },
                    status_code=401,
                )
            else:
                logger.debug(
                    f"No Authorization header provided for {request.url.path}. "
                    f"Will proceed with global/fallback server configuration."
                )
        response = await call_next(request)
        logger.debug(
            f"UserTokenMiddleware.dispatch: EXITED for request "
            f"path='{request.url.path}'"
        )
        return response


_AGENT_INSTRUCTIONS = (
    "# Security Review MCP — Agent Workflow\n\n"
    "Follow this workflow whenever you write or modify code.\n\n"
    "## 1. Before you start coding\n"
    "Call `lightweight_security_review` with a description of what you're building and the tech stack.\n"  # noqa: E501
    "- Use this for any non-trivial coding task to identify risks and get security guidelines upfront.\n"  # noqa: E501
    "- If working from a Jira ticket, call `assess_ticket_security` instead.\n"
    "- For significant new features (auth, file handling, external integrations), also call `perform_threat_model`.\n\n"  # noqa: E501
    "## 2. When adding or updating dependencies\n"
    "Run both steps before writing any code that uses the new packages:\n"
    "1. Call `verify_packages` — confirms packages exist with valid versions. Fix any invalid packages before proceeding.\n"  # noqa: E501
    "2. Call `scan_dependencies` in parallel with step 3 — scans for CVEs and checks reachability. Act on results:\n"  # noqa: E501
    "   - `reachable` or `uncertain` → upgrade or avoid the vulnerable function before continuing.\n"  # noqa: E501
    "   - `not_reachable` / `not_imported` → note it and continue; consider upgrading anyway.\n\n"  # noqa: E501
    "## 3. After generating code\n"
    "Call `verify_code_security` with the generated code.\n"
    "- Run this after every non-trivial code generation before presenting results to the user.\n"  # noqa: E501
    "- Follow the `review_prompt` in the response to perform the analysis and report findings.\n\n"  # noqa: E501
    "## 4. Persisting threat models (optional)\n"
    "After `perform_threat_model`, call `update_threat_model_file` to write `threat-model.md`.\n"  # noqa: E501
    "Call `search_previous_threat_models` first to avoid duplicating existing models.\n"
)

main_mcp = SecurityReviewMCP(
    name="Security Review MCP",
    lifespan=main_lifespan,
    instructions=_AGENT_INSTRUCTIONS,
)
main_mcp.mount("general", general_mcp)
main_mcp.mount("jira", jira_mcp)
main_mcp.mount("confluence", confluence_mcp)
main_mcp.mount("threatmodel", threat_model_mcp)
main_mcp.mount("sca", sca_mcp)


@main_mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
async def _health_check_route(request: Request) -> JSONResponse:
    return await health_check(request)


logger.info("Added /healthz endpoint for Kubernetes probes")
