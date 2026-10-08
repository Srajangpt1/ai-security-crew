"""General security tools that don't require specific providers."""

import json
import logging
from pathlib import Path
from typing import Annotated

from fastmcp import Context, FastMCP
from pydantic import Field

from mcp_security_review.library import (
    SENSITIVE_DATA_TYPES,
    LibraryError,
    UnknownComponentError,
    describe,
    load_library,
)
from mcp_security_review.security import CodeReviewContextBuilder
from mcp_security_review.servers.library_support import (
    library_error,
    split_ids,
    unknown_component_error,
)

logger = logging.getLogger("mcp-security-review.servers.general")

general_mcp = FastMCP(
    name="General Security MCP",
    description="Provider-agnostic security tools for reviews and assessments.",
)


MAX_ALSO_CONSIDER = 8
MAX_TYPICAL_COMPONENTS = 6


@general_mcp.tool(tags={"security", "review", "lightweight"})
async def lightweight_security_review(
    ctx: Context,
    task_description: Annotated[
        str,
        Field(description="Description of the coding task or feature to implement"),
    ],
    components: Annotated[
        str,
        Field(
            description=(
                "Comma-separated component ids the task involves, chosen from the "
                "menu this tool returns when called without components. Leave "
                "empty on the first call to get the menu."
            ),
            default="",
        ),
    ] = "",
    data_handled: Annotated[
        str,
        Field(
            description=(
                "Optional comma-separated kinds of sensitive data involved: "
                + ", ".join(SENSITIVE_DATA_TYPES)
            ),
            default="",
        ),
    ] = "",
    technologies: Annotated[
        str,
        Field(
            description="Technologies/frameworks involved (e.g., 'Python, Django')",
            default="",
        ),
    ] = "",
    project_root: Annotated[
        str,
        Field(
            description=(
                "Project folder. Its .ai-security-crew/library/ files add custom "
                "components, threats, and countermeasures. Defaults to the "
                "server's working directory."
            ),
            default="",
        ),
    ] = "",
) -> str:
    """Perform a lightweight security review before coding (two calls).

    Call 1: pass only task_description. You get a menu of components (things
    like file upload, database, login). Call 2: pass the same task_description
    with the ids of every component the task involves in components. You get
    the threats to guard against and the countermeasures to build in.

    Use this BEFORE starting any coding task so security is built in from the
    start. Pass data_handled when the feature touches credentials, payments, or
    personal data, which raises the risk level one step.

    Args:
        ctx: The FastMCP context.
        task_description: What you're planning to build or implement.
        components: Component ids from the menu (second call).
        data_handled: Kinds of sensitive data involved (optional).
        technologies: Tech stack involved (optional, echoed back).
        project_root: Project folder with optional custom library files.

    Returns:
        JSON. Without components: status "needs_components" and the menu. With
        components: status "complete" with the risk level, threats (most severe
        first), and the countermeasures that mitigate them.

    Example:
        lightweight_security_review("Add avatar upload")
        lightweight_security_review("Add avatar upload", components="file-upload")
    """
    try:
        root = Path(project_root).expanduser() if project_root else None
        library = load_library(root)
    except LibraryError as e:
        return library_error(e, {"task_description": task_description})

    picked = split_ids(components)
    if not picked:
        return json.dumps(
            {
                "success": True,
                "review_type": "lightweight_pre_coding",
                "status": "needs_components",
                "task_description": task_description,
                "instructions": (
                    "Choose the components this change adds or directly modifies "
                    "(usually 2 to 5), then call this tool again with the same "
                    "task_description and components set to their ids "
                    "(comma-separated). Parts of the app this change does not touch "
                    "are out of scope, and components that always come with a pick "
                    "are added for you. Add data_handled if the feature touches "
                    "sensitive data."
                ),
                "components": library.menu(),
                "data_handled_options": list(SENSITIVE_DATA_TYPES),
            },
            separators=(",", ":"),
            ensure_ascii=False,
        )

    try:
        result = library.resolve(picked, split_ids(data_handled))
    except UnknownComponentError as e:
        return unknown_component_error(e, {"task_description": task_description})

    view = describe(result, MAX_ALSO_CONSIDER)
    broad_hint = (
        f"You picked {len(result.picked)} components. Most changes involve 2 to 5; "
        "pick only what this change adds or modifies for a shorter, more relevant "
        "result."
        if len(result.picked) > MAX_TYPICAL_COMPONENTS
        else None
    )
    response = {
        "success": True,
        "review_type": "lightweight_pre_coding",
        "status": "complete",
        "task_description": task_description,
        "technologies": [t.strip() for t in technologies.split(",") if t.strip()],
        "assessment": {
            **view,
            "summary": (
                f"{len(result.threats)} threats and "
                f"{len(result.countermeasures)} countermeasures for "
                f"{', '.join(result.picked)}. Risk level {result.risk_level.value} "
                "(highest threat severity"
                + (", raised for sensitive data" if result.sensitive_data else "")
                + ")."
            ),
        },
        "hint": broad_hint,
        "instructions": (
            "Build these countermeasures in as you write the code, starting with the "
            "most severe threats. These threats come from the components you "
            "picked. also_consider lists general threats from implied components; "
            "pass those components explicitly for full detail. After writing code, "
            "call general_verify_code_security with the same components."
        ),
        "metadata": {
            "total_threats": len(result.threats),
            "total_countermeasures": len(result.countermeasures),
            "also_consider_total": len(result.also_consider),
            "review_purpose": "lightweight_security_guidance",
        },
    }
    return json.dumps(response, separators=(",", ":"), ensure_ascii=False)


@general_mcp.tool(tags={"security", "verification", "code_review"})
async def verify_code_security(
    ctx: Context,
    code: Annotated[
        str,
        Field(description="The source code to review for security vulnerabilities."),
    ],
    file_path: Annotated[
        str,
        Field(
            description="Optional file path, shown in the review (e.g., 'auth.py')",
            default="",
        ),
    ] = "",
    components: Annotated[
        str,
        Field(
            description=(
                "Optional comma-separated component ids the code implements, "
                "the same ids used in lightweight_security_review. Targets the "
                "checklist at their threats."
            ),
            default="",
        ),
    ] = "",
    data_handled: Annotated[
        str,
        Field(
            description=(
                "Optional comma-separated kinds of sensitive data involved: "
                + ", ".join(SENSITIVE_DATA_TYPES)
            ),
            default="",
        ),
    ] = "",
    project_root: Annotated[
        str,
        Field(
            description=(
                "Project folder whose .ai-security-crew/library/ files add custom "
                "entries. Defaults to the server's working directory."
            ),
            default="",
        ),
    ] = "",
) -> str:
    """Request an AI-powered security review of generated code.

    This tool prepares a comprehensive security review context and returns
    structured guidance for you (the AI agent) to analyze the code for
    security vulnerabilities.

    YOU (the AI) will perform the actual security analysis using:
    - The security checklist provided
    - The focus areas for the components you name
    - Your knowledge of security best practices

    Recommended workflow:
    1. Run lightweight_security_review BEFORE coding and note the components
    2. Generate code following the countermeasures it returns
    3. Call this tool with the generated code and the same components
    4. Analyze the code following the review_prompt instructions
    5. Report findings and provide secure code fixes

    Args:
        ctx: The FastMCP context.
        code: The source code to review.
        file_path: Optional file path, shown in the review.
        components: Component ids the code implements (from the pre-coding review).
        data_handled: Kinds of sensitive data involved (optional).
        project_root: Project folder with optional custom library files.

    Returns:
        JSON containing:
        - review_prompt: Detailed instructions for performing the security review
        - security_checklist: Items to verify in the code
        - focus_areas: Specific vulnerability types to look for
        - context: file path, components, and risk level
        - code: The code to review (for reference)

    After receiving this response, analyze the code and provide:
    1. Security assessment (Secure/Needs Attention/Insecure)
    2. List of vulnerabilities found with severity
    3. Specific code fixes for each issue
    4. Checklist results

    Example:
        verify_code_security(code="def login(): ...", file_path="auth.py",
                             components="authentication")
    """
    try:
        library = load_library(
            Path(project_root).expanduser() if project_root else None
        )
    except LibraryError as e:
        return library_error(e, {"code_to_review": code})

    try:
        context_builder = CodeReviewContextBuilder(library)
        review_context = context_builder.build_review_context(
            code=code,
            file_path=file_path if file_path else None,
            components=split_ids(components) or None,
            data_handled=split_ids(data_handled) or None,
        )
    except UnknownComponentError as e:
        return unknown_component_error(e, {"code_to_review": code})

    try:
        # Build response with all context needed for AI review
        response = {
            "success": True,
            "review_type": "ai_powered_security_review",
            "instructions": (
                "IMPORTANT: You (the AI agent) must now perform the security "
                "review. Analyze the code using the checklist and focus areas. "
                "Report all security issues found with severity ratings and fixes."
            ),
            "review_prompt": review_context.review_prompt,
            "context": {
                "file_path": file_path if file_path else "not_specified",
                "components": review_context.components,
                "risk_level": review_context.risk_level,
            },
            "security_checklist": review_context.security_checklist,
            "focus_areas": review_context.review_focus_areas,
            "code_to_review": code,
            "expected_response": {
                "format": "structured_security_review",
                "required_sections": [
                    "overall_assessment",
                    "findings_list",
                    "checklist_results",
                    "recommended_fixes",
                ],
            },
        }
        if not review_context.components:
            response["hint"] = (
                "No components were given, so the checklist is generic. Pass the "
                "component ids from lightweight_security_review for a checklist "
                "aimed at this code's threats."
            )

        return json.dumps(response, indent=2, ensure_ascii=False)

    except (ValueError, KeyError, TypeError) as e:
        error_message = str(e)
        logger.error(f"Failed to build security review context: {error_message}")

        # Even on error, provide basic review guidance
        fallback_response = {
            "success": False,
            "review_type": "ai_powered_security_review",
            "error": error_message,
            "instructions": (
                "Context building failed, but you should still review the code. "
                "Perform a general security review for common vulnerabilities."
            ),
            "fallback_checklist": [
                "No hardcoded passwords, API keys, or secrets",
                "No SQL injection vulnerabilities (use parameterized queries)",
                "No XSS vulnerabilities (sanitize user input in HTML)",
                "No command injection (avoid shell=True, validate inputs)",
                "Proper input validation on all user data",
                "Sensitive data not logged or exposed in errors",
                "Proper error handling without information disclosure",
                "Secure cryptographic practices (no MD5, SHA1 for security)",
            ],
            "code_to_review": code,
            "expected_response": {
                "format": "structured_security_review",
                "required_sections": [
                    "overall_assessment",
                    "findings_list",
                    "recommended_fixes",
                ],
            },
        }

        return json.dumps(fallback_response, indent=2, ensure_ascii=False)
