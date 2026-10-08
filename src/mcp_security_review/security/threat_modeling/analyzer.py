"""Threat model analyzer that coordinates threat model generation.

This module provides the orchestration layer for threat modeling. The actual
threat identification is done by the calling AI agent — this module provides
structure, context enrichment, and reference integration.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from mcp_security_review.security.analyzer import SecurityAnalyzer

from .template import (
    ThreatEntry,
    ThreatModelOutput,
    ThreatModelTemplate,
    ThreatReference,
)

logger = logging.getLogger(__name__)


class ThreatModelAnalyzer:
    """Orchestrates threat model generation with context enrichment.

    Uses SecurityAnalyzer to extract technology and security context from
    artifacts, then structures the output for the AI agent to complete.
    """

    def __init__(self) -> None:
        self.security_analyzer = SecurityAnalyzer()
        self.template = ThreatModelTemplate()

    def build_threat_model_context(
        self,
        title: str,
        description: str,
        artifacts: dict[str, Any],
        previous_models: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Build the full context for the AI agent to generate a threat model.

        Analyzes the provided artifacts for security signals, attaches the
        template structure, and includes any previous threat models as reference.

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

        Returns:
            Dict containing everything the AI agent needs to produce a
            structured threat model.
        """
        # Analyze artifacts for security context
        synthetic_text = self._build_synthetic_text(description, artifacts)
        security_context = self.security_analyzer.analyze_ticket(
            {
                "summary": title,
                "description": synthetic_text,
                "fields": {
                    "issuetype": {"name": "Threat Model"},
                    "labels": artifacts.get("tech_stack", []),
                },
                "comments": [],
            }
        )

        # Build the context payload
        context: dict[str, Any] = {
            "template": self.template.get_template_structure(),
            "feature": {
                "title": title,
                "description": description,
            },
            "artifacts": self._sanitize_artifacts(artifacts),
            "security_signals": {
                "technologies_detected": security_context.technologies,
                "security_categories": list(security_context.security_categories),
                "risk_level": security_context.risk_level,
                "sensitive_data_types": list(security_context.sensitive_data_types),
                "attack_vectors": list(security_context.attack_vectors),
                "security_keywords_found": list(security_context.security_keywords),
            },
            "instructions": (
                "Analyze the provided artifacts using the security signals "
                "as hints. Generate a threat model following the template "
                "structure. Each threat MUST reference specific evidence from "
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

    def _build_synthetic_text(
        self,
        description: str,
        artifacts: dict[str, Any],
    ) -> str:
        """Combine all artifact text for security analysis."""
        parts = [description]

        if artifacts.get("ticket_description"):
            parts.append(str(artifacts["ticket_description"]))

        if artifacts.get("architecture_notes"):
            parts.append(str(artifacts["architecture_notes"]))

        if artifacts.get("data_flows"):
            parts.append(str(artifacts["data_flows"]))

        if artifacts.get("additional_context"):
            parts.append(str(artifacts["additional_context"]))

        if artifacts.get("tech_stack"):
            parts.append("Technologies: " + ", ".join(artifacts["tech_stack"]))

        if artifacts.get("code_snippets"):
            for snippet in artifacts["code_snippets"]:
                if isinstance(snippet, dict):
                    parts.append(snippet.get("code", ""))

        return " ".join(parts)

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
