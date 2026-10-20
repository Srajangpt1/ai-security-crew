"""Typed models for the threat library (components, threats, countermeasures)."""

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

SLUG = r"^[a-z0-9]+(-[a-z0-9]+)*$"

Slug = Annotated[str, StringConstraints(pattern=SLUG)]
CweId = Annotated[str, StringConstraints(pattern=r"^CWE-[1-9][0-9]*$")]
AsvsId = Annotated[str, StringConstraints(pattern=r"^v5\.0\.0-[0-9]+\.[0-9]+\.[0-9]+$")]
McpTop10Id = Annotated[str, StringConstraints(pattern=r"^MCP(0[1-9]|10):2025$")]
# A MITRE ATT&CK Enterprise technique or sub-technique id, such as T1190.
AttackId = Annotated[str, StringConstraints(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")]
# Scanner check ids. Trivy ids are accepted in the current form (AWS-0028)
# and the older AVD-prefixed form (AVD-AWS-0028), which Trivy keeps as an alias.
TrivyId = Annotated[
    str, StringConstraints(pattern=r"^(AVD-)?(AWS|AZU|GCP|DS|KSV)-[0-9]{4}$")
]
CheckovId = Annotated[str, StringConstraints(pattern=r"^CKV2?_[A-Z0-9]+_[0-9]+$")]
ProwlerId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{3,100}$")]
KicsId = Annotated[
    str,
    StringConstraints(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ),
]
CisId = Annotated[str, StringConstraints(pattern=r"^[0-9]+(\.[0-9]+){0,3}$")]
NistId = Annotated[
    str, StringConstraints(pattern=r"^[A-Z]{2}-[0-9]{1,2}(\([0-9]{1,2}\))?$")
]
Provider = Literal["aws", "azure", "gcp", "any"]


class Severity(str, Enum):
    """How bad a threat is if it is exploited."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class Effort(str, Enum):
    """Rough effort to put a countermeasure in place."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Stride(str, Enum):
    """STRIDE threat categories."""

    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information-disclosure"
    DENIAL_OF_SERVICE = "denial-of-service"
    ELEVATION_OF_PRIVILEGE = "elevation-of-privilege"


class _Entry(BaseModel):
    """Fields shared by every library entry."""

    model_config = ConfigDict(extra="forbid")

    id: Slug
    name: Annotated[str, Field(min_length=1)]
    # Only meaningful in user library files: replace a built-in entry of this id.
    override: bool = False


class Component(_Entry):
    """A building block of a feature, such as a database or a file upload."""

    applies_when: Annotated[str, Field(min_length=1)]
    implies: list[Slug] = Field(default_factory=list)
    # A retired component kept so old callers still work. Picking it is the
    # same as picking these components; it is hidden from the menu.
    deprecated_alias_for: list[Slug] = Field(default_factory=list)


class Threat(_Entry):
    """What an attacker (or a mistake) does to one or more components."""

    components: list[Slug]
    severity: Severity
    stride: list[Stride] = Field(default_factory=list)
    cwe: list[CweId] = Field(default_factory=list)
    mcp_top10: list[McpTop10Id] = Field(default_factory=list)
    attack: list[AttackId] = Field(default_factory=list)
    countermeasures: list[Slug]


class ScannerChecks(BaseModel):
    """Ids of the scanner checks that test for a countermeasure (ids only)."""

    model_config = ConfigDict(extra="forbid")

    trivy: list[TrivyId] = Field(default_factory=list)
    checkov: list[CheckovId] = Field(default_factory=list)
    prowler: list[ProwlerId] = Field(default_factory=list)
    kics: list[KicsId] = Field(default_factory=list)


class ComplianceRefs(BaseModel):
    """Benchmark and control ids a countermeasure supports (ids only)."""

    model_config = ConfigDict(extra="forbid")

    cis_aws: list[CisId] = Field(default_factory=list)
    cis_azure: list[CisId] = Field(default_factory=list)
    cis_gcp: list[CisId] = Field(default_factory=list)
    nist_800_53: list[NistId] = Field(default_factory=list)


class Countermeasure(_Entry):
    """What a developer does about a threat."""

    how_to: Annotated[str, Field(min_length=1)]
    effort: Effort
    asvs: list[AsvsId] = Field(default_factory=list)
    # Baseline countermeasures are included in every code review checklist.
    baseline: bool = False
    checks: ScannerChecks | None = None
    compliance: ComplianceRefs | None = None
    # When scanners report this control wrongly, and why.
    false_positives: Annotated[str, Field(min_length=1, max_length=400)] | None = None
    # Clouds the advice applies to; "any" means it does not depend on one.
    providers: list[Provider] = Field(default_factory=list)
