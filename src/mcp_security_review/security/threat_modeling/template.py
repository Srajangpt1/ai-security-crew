"""Developer-focused threat model template and output structures.

Defines the structured output format for threat models, designed for
developers rather than security frameworks. Each threat links back to
concrete evidence (code, artifacts, tickets).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ThreatReference:
    """A reference linking a threat to concrete evidence.

    Attributes:
        type: The kind of reference (code, artifact, ticket, document, url).
        location: Where to find the evidence (file path, URL, ticket key).
        description: Brief explanation of what this reference proves.
        snippet: Optional code or text snippet as inline evidence.
    """

    type: str  # "code", "artifact", "ticket", "document", "url"
    location: str
    description: str
    snippet: str | None = None


@dataclass
class ThreatEntry:
    """A single identified threat in the threat model.

    Attributes:
        id: Short identifier (e.g., "TM-1").
        what_can_go_wrong: Plain-language description of the attack scenario.
        impact: Business impact description (data leak, account takeover, etc.).
        likelihood: How likely this is to happen (high, medium, low).
        data_affected: What data is at risk.
        mitigation: What we're doing or should do about it.
        status: Current status (mitigated, in_progress, accepted, open).
        references: Evidence linking this threat to code/artifacts.
        accepted_risk: If status is "accepted", justification for accepting it.
    """

    id: str
    what_can_go_wrong: str
    impact: str
    likelihood: str  # "high", "medium", "low"
    data_affected: list[str]
    mitigation: str
    status: str = "open"  # "mitigated", "in_progress", "accepted", "open"
    references: list[ThreatReference] = field(default_factory=list)
    accepted_risk: str | None = None


@dataclass
class ThreatModelOutput:
    """Complete threat model output for a feature or component.

    Attributes:
        title: Name of the feature/component being threat modeled.
        description: What we're building — summary of the change/feature.
        author: Who created this threat model.
        created_at: When this threat model was created.
        data_touched: What data this feature touches (flows, storage, PII/secrets).
        technologies: Tech stack involved.
        threats: List of identified threats.
        references_used: Previous threat models or docs used as reference.
        summary: Overall risk summary.
    """

    title: str
    description: str
    author: str
    created_at: str
    data_touched: list[str]
    technologies: list[str]
    threats: list[ThreatEntry]
    references_used: list[dict[str, str]] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "author": self.author,
            "created_at": self.created_at,
            "data_touched": self.data_touched,
            "technologies": self.technologies,
            "threats": [
                {
                    "id": t.id,
                    "what_can_go_wrong": t.what_can_go_wrong,
                    "impact": t.impact,
                    "likelihood": t.likelihood,
                    "data_affected": t.data_affected,
                    "mitigation": t.mitigation,
                    "status": t.status,
                    "references": [
                        {
                            "type": r.type,
                            "location": r.location,
                            "description": r.description,
                            **({"snippet": r.snippet} if r.snippet else {}),
                        }
                        for r in t.references
                    ],
                    **({"accepted_risk": t.accepted_risk} if t.accepted_risk else {}),
                }
                for t in self.threats
            ],
            "references_used": self.references_used,
            "summary": self.summary,
        }

    def to_markdown(self) -> str:
        """Render the threat model as a markdown document for threat-model.md."""
        lines: list[str] = []
        lines.append(f"# Threat Model: {self.title}")
        lines.append("")
        lines.append(f"> **Author:** {self.author}  ")
        lines.append(f"> **Created:** {self.created_at}  ")
        lines.append("")

        # What are we building?
        lines.append("## What Are We Building?")
        lines.append("")
        lines.append(self.description)
        lines.append("")

        # What data does it touch?
        lines.append("## What Data Does It Touch?")
        lines.append("")
        for data_item in self.data_touched:
            lines.append(f"- {data_item}")
        lines.append("")

        # Technologies
        if self.technologies:
            lines.append("## Technologies")
            lines.append("")
            lines.append(", ".join(self.technologies))
            lines.append("")

        # Threats
        lines.append("## What Can Go Wrong?")
        lines.append("")

        for threat in self.threats:
            lines.append(f"### {threat.id}: {threat.what_can_go_wrong}")
            lines.append("")
            lines.append(f"- **Impact:** {threat.impact}")
            lines.append(f"- **Likelihood:** {threat.likelihood}")
            lines.append(f"- **Data Affected:** {', '.join(threat.data_affected)}")
            lines.append(f"- **Status:** {threat.status}")
            lines.append("")

            # Mitigation
            lines.append(f"**Mitigation:** {threat.mitigation}")
            lines.append("")

            # Accepted risk
            if threat.accepted_risk:
                lines.append(f"**Accepted Risk:** {threat.accepted_risk}")
                lines.append("")

            # References / proof
            if threat.references:
                lines.append("**Evidence:**")
                lines.append("")
                for ref in threat.references:
                    ref_label = f"[{ref.type}]"
                    lines.append(f"- {ref_label} `{ref.location}` — {ref.description}")
                    if ref.snippet:
                        lines.append("  ```")
                        for snippet_line in ref.snippet.splitlines():
                            lines.append(f"  {snippet_line}")
                        lines.append("  ```")
                lines.append("")

        # References used
        if self.references_used:
            lines.append("## References")
            lines.append("")
            lines.append("Previous threat models and documents used as reference:")
            lines.append("")
            for ref_item in self.references_used:
                ref_title = ref_item.get("title", "Untitled")
                ref_source = ref_item.get("source", "")
                ref_url = ref_item.get("url", "")
                if ref_url:
                    lines.append(f"- [{ref_title}]({ref_url}) ({ref_source})")
                else:
                    lines.append(f"- {ref_title} ({ref_source})")
            lines.append("")

        # Summary
        if self.summary:
            lines.append("## Summary")
            lines.append("")
            lines.append(self.summary)
            lines.append("")

        lines.append("---")
        lines.append("*Generated by mcp-security-review threat modeling tool*")
        lines.append("")

        return "\n".join(lines)


class ThreatModelTemplate:
    """Provides the template structure that guides the AI agent's threat model output.

    The template defines what sections and fields the agent should produce.
    It does NOT perform the analysis — the calling AI agent does the thinking.
    This just ensures consistent, structured output.
    """

    @staticmethod
    def get_template_structure() -> dict[str, Any]:
        """Return the template structure as a dict for the agent to follow.

        Returns:
            Dictionary describing the expected output structure with
            field descriptions and examples.
        """
        return {
            "template_version": "1.0",
            "instructions": (
                "Use this template to structure your threat model output. "
                "Fill in each section based on the artifacts provided. "
                "Every threat MUST include at least one reference linking it "
                "to concrete evidence (code path, artifact, ticket, or document). "
                "Write threats in plain language — describe attack scenarios "
                "a developer would understand, not abstract security categories."
            ),
            "sections": {
                "title": {
                    "description": (
                        "Name of the feature or component being threat modeled"
                    ),
                    "example": "User Authentication Service Redesign",
                },
                "description": {
                    "description": (
                        "What are we building? Summary of the change/feature"
                    ),
                    "example": (
                        "Migrating from session-based auth to "
                        "JWT tokens with refresh token rotation"
                    ),
                },
                "author": {
                    "description": "Who is creating this threat model",
                    "example": "security-review-mcp",
                },
                "data_touched": {
                    "description": (
                        "What data does this feature touch? "
                        "Include data flows, storage, PII, secrets"
                    ),
                    "example": [
                        "User credentials (email, password hash)",
                        "JWT tokens stored in httpOnly cookies",
                        "Refresh tokens in Redis with 7-day TTL",
                        "User profile data in PostgreSQL",
                    ],
                },
                "technologies": {
                    "description": "Tech stack involved",
                    "example": [
                        "Python",
                        "FastAPI",
                        "PostgreSQL",
                        "Redis",
                        "JWT",
                    ],
                },
                "threats": {
                    "description": (
                        "List of identified threats. Each must link to evidence."
                    ),
                    "fields": {
                        "id": "Short identifier like TM-1, TM-2",
                        "what_can_go_wrong": (
                            "Plain-language attack scenario. "
                            "e.g., 'Attacker steals JWT from "
                            "localStorage and impersonates user'"
                        ),
                        "impact": (
                            "Business impact. e.g., "
                            "'Full account takeover, "
                            "access to user's payment data'"
                        ),
                        "likelihood": "high, medium, or low",
                        "data_affected": "List of data types at risk",
                        "mitigation": ("What we're doing or should do about it"),
                        "status": ("open, in_progress, mitigated, or accepted"),
                        "references": {
                            "description": (
                                "Evidence linking this threat to code or artifacts"
                            ),
                            "fields": {
                                "type": ("code, artifact, ticket, document, or url"),
                                "location": ("File path, URL, or ticket key"),
                                "description": ("What this reference proves"),
                                "snippet": ("Optional inline code/text evidence"),
                            },
                        },
                        "accepted_risk": (
                            "If status is 'accepted', justification for accepting"
                        ),
                    },
                },
            },
            "output_format": (
                "Return the threat model as a JSON object matching the "
                "ThreatModelOutput structure. The tool will handle rendering "
                "it as markdown for threat-model.md if the user approves."
            ),
        }

    @staticmethod
    def get_empty_output(
        title: str,
        description: str,
        author: str = "security-review-mcp",
    ) -> ThreatModelOutput:
        """Create an empty ThreatModelOutput scaffold for the agent to populate.

        Args:
            title: Feature/component name.
            description: What we're building.
            author: Who's creating this.

        Returns:
            ThreatModelOutput with metadata filled but no threats yet.
        """
        return ThreatModelOutput(
            title=title,
            description=description,
            author=author,
            created_at=datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            data_touched=[],
            technologies=[],
            threats=[],
            references_used=[],
            summary="",
        )
