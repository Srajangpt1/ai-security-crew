"""Code security review context builder for AI-powered analysis.

This module prepares security context and review prompts for the AI agent
to perform security analysis on generated code. The focus areas and checklist
come from the threat library for the components the agent names, plus a short
baseline. Nothing scans the code to guess what it does.
"""

from dataclasses import dataclass, field

from mcp_security_review.library import Library, load_library

MAX_FOCUS_AREAS = 12
MAX_COMPONENT_CHECKS = 15


@dataclass
class SecurityReviewContext:
    """Context for AI-powered security review."""

    code: str
    file_path: str | None
    components: list[str] = field(default_factory=list)
    risk_level: str | None = None
    review_focus_areas: list[str] = field(default_factory=list)
    security_checklist: list[str] = field(default_factory=list)
    review_prompt: str = ""


class CodeReviewContextBuilder:
    """Builds context for AI-powered security code review."""

    def __init__(self, library: Library | None = None) -> None:
        self._library = library if library is not None else load_library()

    def build_review_context(
        self,
        code: str,
        file_path: str | None = None,
        components: list[str] | None = None,
        data_handled: list[str] | None = None,
    ) -> SecurityReviewContext:
        """Build context for AI security review.

        Args:
            code: The source code to review.
            file_path: Optional file path, shown in the review prompt.
            components: Library component ids the code implements, as chosen in
                the pre-coding review. Targets the checklist at their threats.
            data_handled: Kinds of sensitive data involved (raises the risk level).

        Returns:
            SecurityReviewContext with all information needed for AI review.

        Raises:
            UnknownComponentError: If a component id is not in the library.
        """
        focus_areas: list[str] = []
        checklist: list[str] = []
        risk_level: str | None = None
        picked: list[str] = []
        covered: set[str] = set()

        if components:
            resolution = self._library.resolve(components, data_handled)
            picked = resolution.picked
            risk_level = resolution.risk_level.value
            focus_areas.extend(t.name for t in resolution.threats)
            for measure in resolution.countermeasures[:MAX_COMPONENT_CHECKS]:
                checklist.append(f"{measure.name}: {measure.how_to}")
                covered.add(measure.id)

        for measure in self._library.baseline_countermeasures():
            if measure.id not in covered:
                checklist.append(f"{measure.name}: {measure.how_to}")

        focus_areas = _unique(focus_areas)[:MAX_FOCUS_AREAS]
        checklist = _unique(checklist)

        review_prompt = self._build_review_prompt(
            code=code,
            file_path=file_path,
            components=picked,
            risk_level=risk_level,
            focus_areas=focus_areas,
            checklist=checklist,
        )

        return SecurityReviewContext(
            code=code,
            file_path=file_path,
            components=picked,
            risk_level=risk_level,
            review_focus_areas=focus_areas,
            security_checklist=checklist,
            review_prompt=review_prompt,
        )

    def _build_review_prompt(
        self,
        code: str,
        file_path: str | None,
        components: list[str],
        risk_level: str | None,
        focus_areas: list[str],
        checklist: list[str],
    ) -> str:
        """Build a comprehensive review prompt for the AI agent."""
        prompt_parts = []

        # Header
        prompt_parts.append("## SECURITY CODE REVIEW REQUEST")
        prompt_parts.append("")

        # Context
        if file_path:
            prompt_parts.append(f"**File:** `{file_path}`")
        if components:
            prompt_parts.append(f"**Components:** {', '.join(components)}")
        if risk_level:
            prompt_parts.append(f"**Risk Level:** {risk_level.upper()}")
        prompt_parts.append("")

        # Instructions
        prompt_parts.append("### Review Instructions")
        prompt_parts.append("")
        prompt_parts.append(
            "Analyze the code below for security vulnerabilities. For each issue found:"
        )
        prompt_parts.append(
            "1. Identify the vulnerability type and severity (Critical/High/Medium/Low)"
        )
        prompt_parts.append("2. Explain why it's a security risk")
        prompt_parts.append("3. Show the problematic code snippet")
        prompt_parts.append("4. Provide a secure code fix")
        prompt_parts.append("")

        # Focus areas
        if focus_areas:
            prompt_parts.append("### Focus Areas")
            prompt_parts.append("")
            prompt_parts.append("Pay special attention to:")
            for area in focus_areas:
                prompt_parts.append(f"- {area}")
            prompt_parts.append("")

        # Checklist
        prompt_parts.append("### Security Checklist")
        prompt_parts.append("")
        prompt_parts.append("Verify each item and report violations:")
        for item in checklist:
            prompt_parts.append(f"- [ ] {item}")
        prompt_parts.append("")

        # Code to review
        prompt_parts.append("### Code to Review")
        prompt_parts.append("")
        prompt_parts.append("```")
        prompt_parts.append(code)
        prompt_parts.append("```")
        prompt_parts.append("")

        # Expected output format
        prompt_parts.append("### Expected Response Format")
        prompt_parts.append("")
        prompt_parts.append("Provide your security review with:")
        prompt_parts.append(
            "1. **Summary:** Overall assessment (Secure/Needs Attention/Insecure)"
        )
        prompt_parts.append(
            "2. **Findings:** List of security issues with severity and fixes"
        )
        prompt_parts.append("3. **Checklist Results:** Which items pass/fail")
        prompt_parts.append("4. **Recommendations:** Prioritized list of actions")

        return "\n".join(prompt_parts)


def _unique(items: list[str]) -> list[str]:
    """Drop duplicates while keeping order."""
    return list(dict.fromkeys(items))
