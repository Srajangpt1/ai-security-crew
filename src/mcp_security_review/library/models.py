"""Typed models for the threat library (components, threats, countermeasures)."""

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

SLUG = r"^[a-z0-9]+(-[a-z0-9]+)*$"

Slug = Annotated[str, StringConstraints(pattern=SLUG)]
CweId = Annotated[str, StringConstraints(pattern=r"^CWE-[1-9][0-9]*$")]
AsvsId = Annotated[str, StringConstraints(pattern=r"^v5\.0\.0-[0-9]+\.[0-9]+\.[0-9]+$")]
McpTop10Id = Annotated[str, StringConstraints(pattern=r"^MCP(0[1-9]|10):2025$")]


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


class Threat(_Entry):
    """What an attacker (or a mistake) does to one or more components."""

    components: list[Slug]
    severity: Severity
    stride: list[Stride] = Field(default_factory=list)
    cwe: list[CweId] = Field(default_factory=list)
    mcp_top10: list[McpTop10Id] = Field(default_factory=list)
    countermeasures: list[Slug]


class Countermeasure(_Entry):
    """What a developer does about a threat."""

    how_to: Annotated[str, Field(min_length=1)]
    effort: Effort
    asvs: list[AsvsId] = Field(default_factory=list)
    # Baseline countermeasures are included in every code review checklist.
    baseline: bool = False
