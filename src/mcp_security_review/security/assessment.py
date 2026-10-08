"""Security assessment and requirements generation.

This module provides the main security assessment functionality that analyzes
tickets and generates security requirements for code generation.
"""

import json
import logging
from dataclasses import asdict, dataclass
from typing import Any

from .analyzer import SecurityAnalyzer, SecurityContext
from .guidelines import SecurityGuideline, SecurityGuidelinesLoader

logger = logging.getLogger(__name__)


@dataclass
class SecurityRequirements:
    """Security requirements generated from ticket analysis."""

    risk_level: str
    security_categories: list[str]
    technologies: list[str]
    guidelines: list[dict[str, Any]]
    prompt_injection: str
    summary: str


class SecurityAssessment:
    """Main security assessment class that coordinates analysis and requirements generation."""

    def __init__(self) -> None:
        self.analyzer = SecurityAnalyzer()
        self.guidelines = SecurityGuidelinesLoader()

    def assess_ticket(self, ticket_data: dict[str, Any]) -> SecurityRequirements:
        """Perform a comprehensive security assessment of a ticket.

        Args:
            ticket_data: ticket data including summary, description, comments, etc.

        Returns:
            SecurityRequirements with security guidelines and prompt injection
        """
        logger.info("Starting security assessment for ticket")

        # Analyze the ticket for security context
        security_context = self.analyzer.analyze_ticket(ticket_data)

        # Get relevant security guidelines
        context_text = self._build_context_text(ticket_data)
        relevant_guidelines = self.guidelines.get_guidelines_for_context(
            context_text, security_context.technologies
        )

        # Filter guidelines based on security categories
        filtered_guidelines = self._filter_guidelines_by_categories(
            relevant_guidelines, security_context.security_categories
        )

        # Generate prompt injection
        prompt_injection = self._generate_prompt_injection(
            security_context, filtered_guidelines
        )

        # Generate summary
        summary = self._generate_summary(security_context, filtered_guidelines)

        # Convert guidelines to dict format
        guidelines_dict = [asdict(guideline) for guideline in filtered_guidelines]

        return SecurityRequirements(
            risk_level=security_context.risk_level,
            security_categories=list(security_context.security_categories),
            technologies=security_context.technologies,
            guidelines=guidelines_dict,
            prompt_injection=prompt_injection,
            summary=summary,
        )

    def _build_context_text(self, ticket_data: dict[str, Any]) -> str:
        """Build context text from ticket data for guideline matching."""
        context_parts = []

        # Add summary
        if "summary" in ticket_data:
            context_parts.append(str(ticket_data["summary"]))

        # Add description
        if "description" in ticket_data:
            context_parts.append(str(ticket_data["description"]))

        # Add issue type
        if "fields" in ticket_data and "issuetype" in ticket_data["fields"]:
            issue_type = ticket_data["fields"]["issuetype"]
            if isinstance(issue_type, dict) and "name" in issue_type:
                context_parts.append(f"Issue type: {issue_type['name']}")

        # Add labels
        if "fields" in ticket_data and "labels" in ticket_data["fields"]:
            labels = ticket_data["fields"]["labels"]
            if isinstance(labels, list) and labels:
                context_parts.append(f"Labels: {', '.join(labels)}")

        return " ".join(context_parts)

    def _filter_guidelines_by_categories(
        self, guidelines: list[SecurityGuideline], categories: set
    ) -> list[SecurityGuideline]:
        """Filter guidelines to only include those relevant to identified categories."""
        if not categories:
            # If no specific categories identified, return top priority guidelines
            return [g for g in guidelines if g.priority in ["critical", "high"]][:5]

        filtered = []
        for guideline in guidelines:
            if guideline.category in categories:
                filtered.append(guideline)

        # If no guidelines match categories, return top priority ones
        if not filtered:
            return [g for g in guidelines if g.priority in ["critical", "high"]][:5]

        return filtered

    def _generate_prompt_injection(
        self, security_context: SecurityContext, guidelines: list[SecurityGuideline]
    ) -> str:
        """Generate security requirements to inject into code generation prompts."""
        injection_parts = []

        # Add security header
        injection_parts.append("🔒 SECURITY REQUIREMENTS:")
        injection_parts.append("")

        # Add risk level warning
        if security_context.risk_level in ["critical", "high"]:
            injection_parts.append(
                f"⚠️  HIGH SECURITY RISK DETECTED ({security_context.risk_level.upper()})"
            )
            injection_parts.append("")

        # Add technology-specific requirements
        if security_context.technologies:
            injection_parts.append("🛠️  TECHNOLOGY-SPECIFIC SECURITY:")
            for tech in security_context.technologies:
                injection_parts.append(
                    f"   • {tech.title()}: Follow secure coding practices"
                )
            injection_parts.append("")

        # Add security categories
        if security_context.security_categories:
            injection_parts.append("🔐 SECURITY CATEGORIES TO ADDRESS:")
            for category in sorted(security_context.security_categories):
                category_name = category.replace("_", " ").title()
                injection_parts.append(f"   • {category_name}")
            injection_parts.append("")

        # Add specific guidelines
        if guidelines:
            injection_parts.append("📋 MANDATORY SECURITY GUIDELINES:")
            injection_parts.append("")

            for guideline in guidelines[:10]:  # Limit to top 10 guidelines
                priority_emoji = {
                    "critical": "🚨",
                    "high": "⚠️",
                    "medium": "📌",
                    "low": "ℹ️",
                }.get(guideline.priority, "📌")

                injection_parts.append(f"{priority_emoji} {guideline.title}")
                injection_parts.append(f"   {guideline.description}")
                injection_parts.append(f"   Implementation: {guideline.implementation}")

                if guideline.examples:
                    injection_parts.append("   Examples:")
                    for example in guideline.examples[:2]:  # Limit examples
                        injection_parts.append(f"     • {example}")

                injection_parts.append("")

        # Add sensitive data handling
        if security_context.sensitive_data_types:
            injection_parts.append("🔒 SENSITIVE DATA HANDLING:")
            injection_parts.append("   • Never log sensitive data")
            injection_parts.append("   • Use proper encryption for storage")
            injection_parts.append("   • Implement data validation and sanitization")
            injection_parts.append("   • Follow data protection regulations")
            injection_parts.append("")

        # Add attack vector prevention
        if security_context.attack_vectors:
            injection_parts.append("🛡️  ATTACK VECTOR PREVENTION:")
            for vector in security_context.attack_vectors:
                vector_name = vector.replace("_", " ").title()
                injection_parts.append(f"   • Prevent {vector_name} attacks")
            injection_parts.append("")

        # Add general security reminders
        injection_parts.append("🔍 GENERAL SECURITY REMINDERS:")
        injection_parts.append("   • Validate all inputs")
        injection_parts.append("   • Use parameterized queries")
        injection_parts.append("   • Implement proper error handling")
        injection_parts.append("   • Follow principle of least privilege")
        injection_parts.append("   • Use secure defaults")
        injection_parts.append("   • Implement proper logging and monitoring")
        injection_parts.append("")

        injection_parts.append(
            "⚠️  IMPORTANT: Review all generated code for security vulnerabilities before deployment!"
        )

        return "\n".join(injection_parts)

    def _generate_summary(
        self, security_context: SecurityContext, guidelines: list[SecurityGuideline]
    ) -> str:
        """Generate a summary of the security assessment."""
        summary_parts = []

        summary_parts.append(
            f"Security Risk Level: {security_context.risk_level.upper()}"
        )

        if security_context.technologies:
            summary_parts.append(
                f"Technologies: {', '.join(security_context.technologies)}"
            )

        if security_context.security_categories:
            categories = [
                cat.replace("_", " ").title()
                for cat in security_context.security_categories
            ]
            summary_parts.append(f"Security Categories: {', '.join(categories)}")

        if security_context.sensitive_data_types:
            summary_parts.append(
                f"Sensitive Data Types: {', '.join(security_context.sensitive_data_types)}"
            )

        if security_context.attack_vectors:
            vectors = [
                vec.replace("_", " ").title() for vec in security_context.attack_vectors
            ]
            summary_parts.append(f"Attack Vectors: {', '.join(vectors)}")

        summary_parts.append(f"Security Guidelines Applied: {len(guidelines)}")

        return " | ".join(summary_parts)

    def to_json(self, requirements: SecurityRequirements) -> str:
        """Convert security requirements to JSON format."""
        return json.dumps(asdict(requirements), indent=2, ensure_ascii=False)

    def from_json(self, json_str: str) -> SecurityRequirements:
        """Create security requirements from JSON format."""
        data = json.loads(json_str)
        return SecurityRequirements(**data)
