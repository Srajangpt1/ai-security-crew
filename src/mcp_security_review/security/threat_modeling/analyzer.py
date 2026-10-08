"""Threat model analyzer that coordinates threat model generation.

This module provides the orchestration layer for threat modeling. The actual
threat identification is done by the calling AI agent — this module provides
structure, context enrichment, and reference integration.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from mcp_security_review.library import Library, describe, load_library

from .template import (
    ThreatEntry,
    ThreatModelOutput,
    ThreatModelTemplate,
    ThreatReference,
)

logger = logging.getLogger(__name__)


class ThreatModelAnalyzer:
    """Orchestrates threat model generation with context enrichment.

    Seeds the threat model with the library's known threats and countermeasures
    for the components the agent names, then structures the output for the AI
    agent to complete.
    """

    def __init__(self, library: Library | None = None) -> None:
        self.library = library if library is not None else load_library()
        self.template = ThreatModelTemplate()

    def build_threat_model_context(
        self,
        title: str,
        description: str,
        artifacts: dict[str, Any],
        previous_models: list[dict[str, Any]] | None = None,
        components: list[str] | None = None,
        data_handled: list[str] | None = None,
    ) -> dict[str, Any]:
        """Build the full context for the AI agent to generate a threat model.

        Attaches the template structure, the library's known threats for the
        named components, and any previous threat models as reference.

        Args:
            title: Name of the feature/component.
            description: What's being built or changed.
            artifacts: Input artifacts. Supported keys:
                - code_snippets: list[dict] with {file_path, code, language}
                - data_flows: str describing data flows (text or mermaid)
                - tech_stack: list[str] of technologies
                - ticket_description: str from an issue-tracker ticket
                - architecture_notes: str with architecture context
                - additional_context: str with any other context
            previous_models: Previous threat models for reference. Each dict
                should have at minimum {title, source, content} or {title, url}.
            components: Library component ids the feature involves.
            data_handled: Kinds of sensitive data involved (raises the risk level).

        Returns:
            Dict containing everything the AI agent needs to produce a
            structured threat model.

        Raises:
            UnknownComponentError: If a component id is not in the library.
        """

        # Build the context payload
        context: dict[str, Any] = {
            "template": self.template.get_template_structure(),
            "feature": {
                "title": title,
                "description": description,
            },
            "artifacts": self._sanitize_artifacts(artifacts),
            "known_threats": self._known_threats(components, data_handled),
            "instructions": (
                "Analyze the provided artifacts using known_threats as a starting "
                "checklist: keep the ones that apply, drop the ones that do not, "
                "and add scenarios specific to these artifacts. Generate a threat "
                "model following the template structure. Each threat MUST reference specific evidence from "
                "the artifacts (code paths, data flows, architecture decisions). "
                "Write threats in plain developer language. Focus on concrete "
                "attack scenarios, not abstract categories."
            ),
        }

        # Attach previous models as reference
        if previous_models:
            context["previous_threat_models"] = [
                {
                    "title": model.get("title", "Untitled"),
                    "source": model.get("source", "unknown"),
                    "url": model.get("url", ""),
                    "summary": model.get("summary", ""),
                    "content": model.get("content", "")[:2000],
                }
                for model in previous_models
            ]
            context["reference_instructions"] = (
                "Previous threat models from the team are provided above. "
                "Use them as reference for tone, depth, and coverage patterns. "
                "Do NOT copy threats — use them to inform your analysis of "
                "the current feature."
            )

        return context

    def parse_threat_model_response(
        self,
        response_data: dict[str, Any],
    ) -> ThreatModelOutput:
        """Parse the AI agent's threat model response into a structured output.

        Args:
            response_data: The threat model data from the AI agent, expected
                to follow the template structure.

        Returns:
            ThreatModelOutput ready for markdown rendering or JSON export.
        """
        threats: list[ThreatEntry] = []
        for threat_data in response_data.get("threats", []):
            references = []
            for ref_data in threat_data.get("references", []):
                references.append(
                    ThreatReference(
                        type=ref_data.get("type", "artifact"),
                        location=ref_data.get("location", ""),
                        description=ref_data.get("description", ""),
                        snippet=ref_data.get("snippet"),
                    )
                )

            threats.append(
                ThreatEntry(
                    id=threat_data.get("id", f"TM-{len(threats) + 1}"),
                    what_can_go_wrong=threat_data.get("what_can_go_wrong", ""),
                    impact=threat_data.get("impact", ""),
                    likelihood=threat_data.get("likelihood", "medium"),
                    data_affected=threat_data.get("data_affected", []),
                    mitigation=threat_data.get("mitigation", ""),
                    status=threat_data.get("status", "open"),
                    references=references,
                    accepted_risk=threat_data.get("accepted_risk"),
                )
            )

        return ThreatModelOutput(
            title=response_data.get("title", "Untitled Threat Model"),
            description=response_data.get("description", ""),
            author=response_data.get("author", "security-review-mcp"),
            created_at=response_data.get(
                "created_at",
                datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            ),
            data_touched=response_data.get("data_touched", []),
            technologies=response_data.get("technologies", []),
            threats=threats,
            references_used=response_data.get("references_used", []),
            summary=response_data.get("summary", ""),
        )

    def _known_threats(
        self,
        components: list[str] | None,
        data_handled: list[str] | None,
    ) -> dict[str, Any]:
        """Return library threats for the components, or the menu to pick from."""
        if not components:
            return {
                "status": "needs_components",
                "hint": (
                    "No components were given, so there are no library threats. "
                    "Call this tool again with components set to the ids of the "
                    "parts this feature adds or changes (usually 2 to 5), or use "
                    "the ids you picked in lightweight_security_review."
                ),
                "components": self.library.menu(),
            }
        resolution = self.library.resolve(components, data_handled)
        return {"status": "from_library", **describe(resolution)}

    def _sanitize_artifacts(
        self,
        artifacts: dict[str, Any],
    ) -> dict[str, Any]:
        """Sanitize artifacts for inclusion in the context payload.

        Ensures code snippets aren't excessively large.
        """
        sanitized = dict(artifacts)

        if "code_snippets" in sanitized:
            trimmed_snippets = []
            for snippet in sanitized["code_snippets"]:
                if isinstance(snippet, dict):
                    code = snippet.get("code", "")
                    if len(code) > 5000:
                        code = (
                            code[:5000]
                            + "\n... [truncated, "
                            + str(len(code))
                            + " chars total]"
                        )
                    trimmed_snippets.append(
                        {
                            "file_path": snippet.get("file_path", "unknown"),
                            "code": code,
                            "language": snippet.get("language", ""),
                        }
                    )
            sanitized["code_snippets"] = trimmed_snippets

        return sanitized
