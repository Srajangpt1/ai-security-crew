"""The loaded threat library and the component -> threat -> countermeasure lookup."""

from dataclasses import dataclass, field
from typing import Any

from .models import SEVERITY_RANK, Component, Countermeasure, Severity, Threat

SENSITIVE_DATA_TYPES = (
    "credentials",
    "payments",
    "personal_data",
    "health_data",
    "secrets",
)

_LEVELS_UP = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class UnknownComponentError(ValueError):
    """Raised when a requested component id is not in the library."""

    def __init__(self, unknown: list[str], valid: list[str]) -> None:
        super().__init__(f"Unknown component(s): {', '.join(unknown)}")
        self.unknown = unknown
        self.valid = valid


@dataclass
class Resolution:
    """The result of resolving a set of components against the library.

    ``threats`` are those that apply to a component the caller picked. They drive
    the countermeasures and the risk level. ``also_consider`` holds threats that
    only apply to components pulled in through ``implies`` (for example the generic
    web endpoint threats behind a file upload), so they stay visible without
    taking over the result.
    """

    components: list[str]
    picked: list[str]
    threats: list[Threat]
    also_consider: list[Threat]
    countermeasures: list[Countermeasure]
    mitigates: dict[str, list[str]]
    risk_level: Severity
    sensitive_data: list[str] = field(default_factory=list)


@dataclass
class Library:
    """All components, threats, and countermeasures, indexed by id."""

    components: dict[str, Component]
    threats: dict[str, Threat]
    countermeasures: dict[str, Countermeasure]

    def baseline_countermeasures(self) -> list[Countermeasure]:
        """Countermeasures that belong in every code review checklist."""
        return [m for m in self.countermeasures.values() if m.baseline]

    def menu(self) -> list[dict[str, str]]:
        """Return the component menu shown to the agent."""
        return [
            {"id": c.id, "name": c.name, "applies_when": c.applies_when}
            for c in self.components.values()
        ]

    def expand(self, component_ids: list[str]) -> list[str]:
        """Add implied components, keep order, and reject unknown ids."""
        unknown = [c for c in component_ids if c not in self.components]
        if unknown:
            raise UnknownComponentError(unknown, list(self.components))

        expanded: list[str] = []
        pending = list(component_ids)
        while pending:
            current = pending.pop(0)
            if current in expanded:
                continue
            expanded.append(current)
            pending.extend(self.components[current].implies)
        return expanded

    def resolve(
        self, component_ids: list[str], sensitive_data: list[str] | None = None
    ) -> Resolution:
        """Find the threats and countermeasures for the given components.

        Args:
            component_ids: Components the feature involves.
            sensitive_data: Kinds of sensitive data handled, which raise the
                risk level by one step.

        Returns:
            The threats (most severe first), the countermeasures that mitigate
            them, lesser-priority threats from implied components, and the
            overall risk level.

        Raises:
            UnknownComponentError: If a component id is not in the library.
        """
        expanded = self.expand(component_ids)
        picked = set(component_ids)
        selected = set(expanded)

        threats = [
            t for t in self.threats.values() if picked.intersection(t.components)
        ]
        also_consider = [
            t
            for t in self.threats.values()
            if selected.intersection(t.components)
            and not picked.intersection(t.components)
        ]
        threats.sort(key=lambda t: (SEVERITY_RANK[t.severity], t.id))
        also_consider.sort(key=lambda t: (SEVERITY_RANK[t.severity], t.id))

        mitigates: dict[str, list[str]] = {}
        ordered_ids: list[str] = []
        for threat in threats:
            for cm_id in threat.countermeasures:
                if cm_id not in mitigates:
                    mitigates[cm_id] = []
                    ordered_ids.append(cm_id)
                mitigates[cm_id].append(threat.id)

        normalized = (s.strip().lower().replace("-", "_") for s in sensitive_data or [])
        sensitive = list(
            dict.fromkeys(s for s in normalized if s in SENSITIVE_DATA_TYPES)
        )
        return Resolution(
            components=expanded,
            picked=list(dict.fromkeys(component_ids)),
            threats=threats,
            also_consider=also_consider,
            countermeasures=[self.countermeasures[i] for i in ordered_ids],
            mitigates=mitigates,
            risk_level=_risk_level(threats, bool(sensitive)),
            sensitive_data=sensitive,
        )


def _risk_level(threats: list[Threat], handles_sensitive_data: bool) -> Severity:
    """Highest threat severity, raised one step when sensitive data is handled."""
    if not threats:
        return Severity.LOW
    top = min((t.severity for t in threats), key=lambda s: SEVERITY_RANK[s])
    if handles_sensitive_data:
        index = min(_LEVELS_UP.index(top) + 1, len(_LEVELS_UP) - 1)
        return _LEVELS_UP[index]
    return top


def summarize(resolution: Resolution) -> dict[str, Any]:
    """Return counts used in the tool's summary line."""
    by_severity: dict[str, int] = {}
    for threat in resolution.threats:
        by_severity[threat.severity.value] = (
            by_severity.get(threat.severity.value, 0) + 1
        )
    return {
        "threats": len(resolution.threats),
        "countermeasures": len(resolution.countermeasures),
        "by_severity": by_severity,
    }


def describe(resolution: Resolution, max_also_consider: int = 8) -> dict[str, Any]:
    """Return the compact, JSON-ready view of a resolution used by the tools."""
    return {
        "risk_level": resolution.risk_level.value,
        "components": resolution.picked,
        "implied_components": [
            c for c in resolution.components if c not in resolution.picked
        ],
        "sensitive_data": resolution.sensitive_data,
        "threats": [
            {
                "id": t.id,
                "name": t.name,
                "severity": t.severity.value,
                "cwe": t.cwe,
            }
            for t in resolution.threats
        ],
        "countermeasures": [
            {
                "id": m.id,
                "name": m.name,
                "how_to": m.how_to,
                "effort": m.effort.value,
                "asvs": m.asvs,
                "mitigates": resolution.mitigates[m.id],
            }
            for m in resolution.countermeasures
        ],
        "also_consider": [
            {"id": t.id, "name": t.name, "severity": t.severity.value}
            for t in resolution.also_consider[:max_also_consider]
        ],
    }
