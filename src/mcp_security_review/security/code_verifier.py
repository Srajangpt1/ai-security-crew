"""Code security review context builder for AI-powered analysis.

This module prepares the checklist and review prompt the AI agent uses to review
code it already has in context. The focus areas and checklist come from the threat
library for the components the agent names, plus a short baseline. The code itself
is never passed in, scanned, or returned.
"""

from dataclasses import dataclass, field

from mcp_security_review.library import Library, load_library
from mcp_security_review.library.models import Countermeasure, Threat
from mcp_security_review.providers.attack import AttackIndex

MAX_FOCUS_AREAS = 12
MAX_COMPONENT_CHECKS = 15
# Infrastructure checklists list every countermeasure up to this many: each is a
# setting the agent can check, and cutting them would drop whole resource types.
MAX_IAC_CHECKS = 40
IAC_COMPONENTS = ("container-image", "kubernetes", "ci-pipeline")


@dataclass
class SecurityReviewContext:
    """Context for AI-powered security review."""

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
        file_path: str | None = None,
        components: list[str] | None = None,
        data_handled: list[str] | None = None,
        attack: AttackIndex | None = None,
    ) -> SecurityReviewContext:
        """Build context for AI security review.

        Args:
            file_path: Optional file path, shown in the review prompt.
            components: Library component ids the code implements, as chosen in
                the pre-coding review. Targets the checklist at their threats.
            data_handled: Kinds of sensitive data involved (raises the risk level).
            attack: A loaded ATT&CK index. With it, a focus area whose threat
                maps to a known technique names it, e.g.
                `"... (ATT&CK T1190 Exploit Public-Facing Application)"`.

        Returns:
            SecurityReviewContext with all information needed for AI review.
            Countermeasures for threats on picked infrastructure components
            (see `is_iac_component`) carry their scanner check ids, compliance
            ids, and false positive note. When only infrastructure components
            are picked, the app-code baseline is left out; mixed picks keep it.

        Raises:
            UnknownComponentError: If a component id is not in the library.
        """
        focus_areas: list[str] = []
        checklist: list[str] = []
        risk_level: str | None = None
        picked: list[str] = []
        covered: set[str] = set()

        iac_only = False
        if components:
            resolution = self._library.resolve(components, data_handled)
            picked = resolution.picked
            iac_picked = {c for c in picked if is_iac_component(c)}
            iac_only = bool(iac_picked) and len(iac_picked) == len(picked)
            risk_level = resolution.risk_level.value
            focus_areas.extend(_focus_area(t, attack) for t in resolution.threats)
            # Countermeasures for a threat on a picked infrastructure component
            # get the infrastructure format and limit; the rest stay app items.
            iac_threats = {
                t.id
                for t in resolution.threats
                if iac_picked.intersection(t.components)
            }
            iac_measures = [
                m
                for m in resolution.countermeasures
                if iac_threats.intersection(resolution.mitigates[m.id])
            ]
            iac_ids = {m.id for m in iac_measures}
            app_measures = [
                m for m in resolution.countermeasures if m.id not in iac_ids
            ]
            for measure in iac_measures[:MAX_IAC_CHECKS]:
                checklist.append(_iac_item(measure))
                covered.add(measure.id)
            for measure in app_measures[:MAX_COMPONENT_CHECKS]:
                checklist.append(_item(measure))
                covered.add(measure.id)

        # Infrastructure-only picks keep only the provider-neutral baseline items
        # (secrets and logging); the rest of the baseline is about app code, so
        # a pick that also names app components keeps all of it.
        for measure in self._library.baseline_countermeasures():
            if measure.id in covered or (iac_only and "any" not in measure.providers):
                continue
            checklist.append(_item(measure))

        focus_areas = _unique(focus_areas)[:MAX_FOCUS_AREAS]
        checklist = _unique(checklist)

        review_prompt = self._build_review_prompt(
            file_path=file_path,
            components=picked,
            risk_level=risk_level,
            focus_areas=focus_areas,
            checklist=checklist,
        )

        return SecurityReviewContext(
            file_path=file_path,
            components=picked,
            risk_level=risk_level,
            review_focus_areas=focus_areas,
            security_checklist=checklist,
            review_prompt=review_prompt,
        )

    def _build_review_prompt(
        self,
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
            "Review the code you just wrote (it is already in your context) for "
            "security vulnerabilities. For each issue found:"
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


def is_iac_component(component_id: str) -> bool:
    """Whether a component is infrastructure code (cloud, image, cluster, CI)."""
    return component_id.startswith("cloud-") or component_id in IAC_COMPONENTS


def _item(measure: Countermeasure) -> str:
    """Plain checklist line."""
    return f"{measure.name}: {measure.how_to}"


def _iac_item(measure: Countermeasure) -> str:
    """Checklist line with scanner and compliance ids and the false positive note.

    For example `"<name>: <how_to> [Trivy AVD-AWS-0028; Checkov CKV_AWS_79;
    Prowler ec2_instance_imdsv2_enabled; CIS AWS 6.7] (false positive: ...)"`.
    """
    refs: list[tuple[str, list[str]]] = []
    if measure.checks is not None:
        refs += [
            ("Trivy", measure.checks.trivy),
            ("Checkov", measure.checks.checkov),
            ("Prowler", measure.checks.prowler),
            ("KICS", measure.checks.kics),
        ]
    if measure.compliance is not None:
        refs += [
            ("CIS AWS", measure.compliance.cis_aws),
            ("CIS Azure", measure.compliance.cis_azure),
            ("CIS GCP", measure.compliance.cis_gcp),
            ("NIST 800-53", measure.compliance.nist_800_53),
        ]
    text = _item(measure)
    listed = [f"{label} {', '.join(ids)}" for label, ids in refs if ids]
    if listed:
        text += f" [{'; '.join(listed)}]"
    if measure.false_positives:
        text += f" (false positive: {measure.false_positives})"
    return text


def _focus_area(threat: Threat, attack: AttackIndex | None) -> str:
    """Name a threat with its first current ATT&CK technique the index knows.

    Techniques ATT&CK has revoked or deprecated are skipped.
    """
    if attack is not None:
        for tid in threat.attack:
            tech = attack.technique(tid)
            if tech is None or tech.get("revoked") or tech.get("deprecated"):
                continue
            return f"{threat.name} (ATT&CK {tech['id']} {tech['name']})"
    return threat.name


def _unique(items: list[str]) -> list[str]:
    """Drop duplicates while keeping order."""
    return list(dict.fromkeys(items))
