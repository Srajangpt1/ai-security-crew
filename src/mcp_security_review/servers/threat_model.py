"""Threat modeling MCP tools for developer-focused threat analysis.

Provides tools to perform threat models and update a local threat-model.md
file.
"""

import json
import logging
from typing import Annotated, Any

from fastmcp import Context, FastMCP
from pydantic import Field

from mcp_security_review.security.threat_modeling import (
    ThreatModelAnalyzer,
    ThreatModelTemplate,
)

logger = logging.getLogger("mcp-security-review.servers.threat_model")

threat_model_mcp = FastMCP(
    name="Threat Model MCP",
    description="Developer-focused threat modeling tools with reference support.",
)


@threat_model_mcp.tool(tags={"security", "threat_model", "read"})
async def perform_threat_model(
    ctx: Context,
    title: Annotated[
        str,
        Field(description="Name of the feature or component to threat model"),
    ],
    description: Annotated[
        str,
        Field(
            description=(
                "What are we building? Describe the feature, change, "
                "or component being threat modeled"
            )
        ),
    ],
    code_snippets: Annotated[
        str,
        Field(
            description=(
                "Optional JSON array of code snippets to analyze. "
                'Each entry: {"file_path": "...", "code": "...", "language": "..."}'
            ),
            default="",
        ),
    ] = "",
    data_flows: Annotated[
        str,
        Field(
            description=(
                "Optional description of data flows — plain text or "
                "mermaid diagram describing how data moves through the system"
            ),
            default="",
        ),
    ] = "",
    tech_stack: Annotated[
        str,
        Field(
            description=(
                "Optional comma-separated list of technologies involved "
                "(e.g., 'Python, FastAPI, PostgreSQL, Redis')"
            ),
            default="",
        ),
    ] = "",
    architecture_notes: Annotated[
        str,
        Field(
            description=(
                "Optional architecture context — design decisions, "
                "system boundaries, deployment model"
            ),
            default="",
        ),
    ] = "",
    additional_context: Annotated[
        str,
        Field(
            description=(
                "Optional additional context — ticket descriptions, "
                "requirements, or any other relevant information"
            ),
            default="",
        ),
    ] = "",
    previous_models_json: Annotated[
        str,
        Field(
            description=(
                "Optional JSON array of previous threat models for reference. "
                "Each entry should have: "
                '{"title": "...", "source": "...", "content": "...", "url": "..."}'
            ),
            default="",
        ),
    ] = "",
) -> str:
    """Generate a developer-focused threat model for a feature or component.

    This tool analyzes the provided artifacts, enriches them with security
    signals (technologies, attack vectors, sensitive data patterns), and
    returns a structured context for you (the AI agent) to produce the
    actual threat model.

    YOU (the AI agent) will:
    1. Analyze the artifacts and security signals provided
    2. Identify concrete threats with plain-language attack scenarios
    3. Link each threat to evidence from the provided artifacts
    4. Suggest mitigations for each identified threat
    5. Return a structured threat model following the template

    After generating the threat model, you SHOULD ask the user if they
    want to save it to a threat-model.md file using the
    update_threat_model_file tool.

    This tool does NOT collide with lightweight_security_review or
    verify_code_security — those are for pre/post coding security
    guidance. This tool produces a standalone threat model document.

    Args:
        ctx: The FastMCP context.
        title: Feature or component name.
        description: What we're building.
        code_snippets: JSON array of code to analyze.
        data_flows: Data flow descriptions.
        tech_stack: Comma-separated technologies.
        architecture_notes: Architecture context.
        additional_context: Any other relevant context.
        previous_models_json: Previous threat models as JSON for reference.

    Returns:
        JSON containing:
        - template: The threat model structure to follow
        - artifacts: The provided artifacts for analysis
        - security_signals: Auto-detected security context
        - previous_threat_models: Reference models (if provided)
        - instructions: How to produce the threat model
        - suggest_file_update: Whether to prompt the user about threat-model.md

    Example:
        perform_threat_model(
            title="JWT Auth Migration",
            description="Migrating from session-based auth to JWT tokens",
            tech_stack="Python, FastAPI, Redis",
            data_flows="User -> API Gateway -> Auth Service -> Redis (token store)"
        )
    """
    try:
        # Parse code snippets if provided
        parsed_code_snippets: list[dict[str, str]] = []
        if code_snippets and code_snippets.strip():
            try:
                parsed_code_snippets = json.loads(code_snippets)
                if not isinstance(parsed_code_snippets, list):  # type: ignore[unreachable]
                    parsed_code_snippets = []
            except json.JSONDecodeError:
                logger.warning(
                    "Invalid JSON in code_snippets, treating as single snippet"
                )
                parsed_code_snippets = [
                    {
                        "file_path": "provided_code",
                        "code": code_snippets,
                        "language": "",
                    }
                ]

        # Parse tech stack
        parsed_tech_stack = (
            [t.strip() for t in tech_stack.split(",") if t.strip()]
            if tech_stack
            else []
        )

        # Parse previous models if provided
        parsed_previous_models: list[dict[str, Any]] = []
        if previous_models_json and previous_models_json.strip():
            try:
                parsed_previous_models = json.loads(previous_models_json)
                if not isinstance(parsed_previous_models, list):  # type: ignore[unreachable]
                    parsed_previous_models = []
            except json.JSONDecodeError:
                logger.warning("Invalid JSON in previous_models_json, ignoring")

        # Build artifacts dict
        artifacts: dict[str, Any] = {}
        if parsed_code_snippets:
            artifacts["code_snippets"] = parsed_code_snippets
        if data_flows:
            artifacts["data_flows"] = data_flows
        if parsed_tech_stack:
            artifacts["tech_stack"] = parsed_tech_stack
        if architecture_notes:
            artifacts["architecture_notes"] = architecture_notes
        if additional_context:
            artifacts["additional_context"] = additional_context

        # Build threat model context
        analyzer = ThreatModelAnalyzer()
        context = analyzer.build_threat_model_context(
            title=title,
            description=description,
            artifacts=artifacts,
            previous_models=parsed_previous_models or None,
        )

        # Wrap with metadata
        response: dict[str, Any] = {
            "success": True,
            "tool": "perform_threat_model",
            **context,
            "output_instructions": (
                "After analyzing the artifacts and security signals, return "
                "a JSON object matching the template structure with all "
                "threats identified. Each threat MUST include at least one "
                "reference with evidence. Use the parse format described in "
                "the template."
            ),
            "suggest_file_update": True,
            "file_update_message": (
                "After generating the threat model, ask the user: "
                "'Would you like me to save this threat model to "
                "threat-model.md?' If they agree, use the "
                "update_threat_model_file tool with the generated content."
            ),
        }

        return json.dumps(response, indent=2, ensure_ascii=False)

    except (ValueError, KeyError, TypeError) as e:
        error_message = str(e)
        logger.error(f"Threat model generation failed: {error_message}")

        # Return template anyway so agent can still attempt the analysis
        fallback_response: dict[str, Any] = {
            "success": False,
            "error": error_message,
            "template": ThreatModelTemplate.get_template_structure(),
            "feature": {
                "title": title,
                "description": description,
            },
            "instructions": (
                "Context enrichment failed, but you should still produce "
                "a threat model based on the description and any artifacts "
                "the user has provided. Follow the template structure."
            ),
            "suggest_file_update": True,
            "file_update_message": (
                "After generating the threat model, ask the user: "
                "'Would you like me to save this threat model to "
                "threat-model.md?'"
            ),
        }
        return json.dumps(fallback_response, indent=2, ensure_ascii=False)


@threat_model_mcp.tool(tags={"security", "threat_model", "write"})
async def update_threat_model_file(
    ctx: Context,
    threat_model_json: Annotated[
        str,
        Field(
            description=(
                "The threat model data as a JSON object following the "
                "ThreatModelOutput structure from perform_threat_model. "
                "Must include: title, description, author, data_touched, "
                "technologies, threats (with references), and summary."
            )
        ),
    ],
    file_path: Annotated[
        str,
        Field(
            description=(
                "Path to the threat-model.md file to create or update. "
                "Defaults to 'threat-model.md' in the current directory."
            ),
            default="threat-model.md",
        ),
    ] = "threat-model.md",
    append: Annotated[  # noqa: FBT002
        bool,
        Field(
            description=(
                "If true, append this threat model to the existing file "
                "instead of replacing it. Useful when the file contains "
                "multiple threat models."
            ),
            default=False,
        ),
    ] = False,
) -> str:
    """Write or update a threat-model.md file with the generated threat model.

    This tool should ONLY be called after the user has confirmed they want
    to save the threat model. The calling agent must prompt the user first.

    Takes the structured threat model JSON output and renders it as a
    developer-friendly markdown document with linked references and evidence.

    Args:
        ctx: The FastMCP context.
        threat_model_json: The threat model data as JSON.
        file_path: Path to write the markdown file.
        append: Whether to append to existing file or replace.

    Returns:
        JSON with success status and the file path written.

    Example:
        update_threat_model_file(
            threat_model_json='{"title": "Auth Service", ...}',
            file_path="docs/threat-model.md"
        )
    """
    try:
        # Parse the threat model data
        threat_model_data = json.loads(threat_model_json)

        # Parse into structured output
        analyzer = ThreatModelAnalyzer()
        threat_model = analyzer.parse_threat_model_response(threat_model_data)

        # Render as markdown
        markdown_content = threat_model.to_markdown()

        # Write or append to file
        if append:
            try:
                with open(file_path, encoding="utf-8") as f:
                    existing_content = f.read()
                markdown_content = existing_content.rstrip() + "\n\n" + markdown_content
            except FileNotFoundError:
                pass  # File doesn't exist yet, will create it

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)

        # Count stats for response
        threat_count = len(threat_model.threats)
        ref_count = sum(len(t.references) for t in threat_model.threats)
        mitigated_count = sum(
            1 for t in threat_model.threats if t.status == "mitigated"
        )
        open_count = sum(1 for t in threat_model.threats if t.status == "open")

        response: dict[str, Any] = {
            "success": True,
            "file_path": file_path,
            "action": "appended" if append else "created",
            "stats": {
                "threats_documented": threat_count,
                "references_linked": ref_count,
                "mitigated": mitigated_count,
                "open": open_count,
            },
            "message": (
                f"Threat model '{threat_model.title}' written to {file_path}. "
                f"{threat_count} threats documented with {ref_count} references."
            ),
        }

        return json.dumps(response, indent=2, ensure_ascii=False)

    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in threat_model_json: {e}")
        return json.dumps(
            {
                "success": False,
                "error": f"Invalid JSON: {e}",
                "message": (
                    "The threat model data is not valid JSON. Ensure it "
                    "follows the ThreatModelOutput structure."
                ),
            },
            indent=2,
            ensure_ascii=False,
        )
    except OSError as e:
        logger.error(f"Failed to write threat model file: {e}")
        return json.dumps(
            {
                "success": False,
                "error": f"File write error: {e}",
                "message": (
                    f"Could not write to {file_path}. Check that the "
                    "directory exists and is writable."
                ),
            },
            indent=2,
            ensure_ascii=False,
        )
    except (ValueError, KeyError, TypeError) as e:
        logger.error(f"Failed to parse threat model data: {e}")
        return json.dumps(
            {
                "success": False,
                "error": str(e),
                "message": (
                    "Failed to parse the threat model data. Ensure it "
                    "matches the expected structure from perform_threat_model."
                ),
            },
            indent=2,
            ensure_ascii=False,
        )
