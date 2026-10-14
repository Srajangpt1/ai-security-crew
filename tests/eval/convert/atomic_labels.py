"""Load the human-reviewed label file for Atomic Red Team tests."""

from dataclasses import dataclass
from pathlib import Path

import yaml


class MissingLabelError(Exception):
    """Raised when a test has no entry in the label file."""


@dataclass(frozen=True)
class Label:
    """One reviewed judgement for a test.

    Attributes:
        label: Either ``HARMFUL`` or ``BORDERLINE``.
        tactic: Lowercase MITRE tactic slug used as the case ``category``.
        reason: Short human-written justification, data only.
        user_request: BORDERLINE only: a plausible dev request leading to
            this exact command.
        description: BORDERLINE only: a short, specific description of what
            the command does, used as the ``normal`` case's notes.
        context_dependent: HARMFUL only: true when a reasonable developer
            or sysadmin could run this exact command for a legitimate
            reason with no attacker involved. Such tests only emit the
            with-injection attack case, never the no-context variant.
        context_reason: Why ``context_dependent`` was set, data only.
    """

    label: str
    tactic: str
    reason: str
    user_request: str = ""
    description: str = ""
    context_dependent: bool = False
    context_reason: str = ""


def load_labels(path: Path) -> dict[tuple[str, int], Label]:
    """Read ``atomic_labels.yaml`` into a lookup keyed by (technique, index).

    Args:
        path: Path to the YAML label file.

    Returns:
        Mapping from (technique id, 1-based test index) to its ``Label``.

    Raises:
        ValueError: If an entry is missing a required field or has an
            unrecognized ``label`` value.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    out: dict[tuple[str, int], Label] = {}
    for entry in raw:
        try:
            technique = str(entry["technique"])
            index = int(entry["index"])
            label = str(entry["label"])
            tactic = str(entry["tactic"])
            reason = str(entry["reason"])
        except KeyError as exc:
            msg = f"label entry missing field: {exc}"
            raise ValueError(msg) from exc
        if label not in ("HARMFUL", "BORDERLINE"):
            msg = f"unknown label {label!r} for {technique}#{index}"
            raise ValueError(msg)
        user_request = str(entry.get("user_request", ""))
        description = str(entry.get("description", ""))
        if label == "BORDERLINE" and not (user_request and description):
            msg = (
                f"BORDERLINE entry {technique}#{index} needs "
                "user_request and description"
            )
            raise ValueError(msg)
        context_dependent = bool(entry.get("context_dependent", False))
        context_reason = str(entry.get("context_reason", ""))
        if context_dependent and label != "HARMFUL":
            msg = f"context_dependent set on non-HARMFUL entry {technique}#{index}"
            raise ValueError(msg)
        out[(technique, index)] = Label(
            label,
            tactic,
            reason,
            user_request,
            description,
            context_dependent,
            context_reason,
        )
    return out


def require_label(
    labels: dict[tuple[str, int], Label], technique: str, index: int
) -> Label:
    """Look up a test's label, failing clearly if it is missing.

    Args:
        labels: Mapping produced by :func:`load_labels`.
        technique: Technique id (e.g. ``T1048.003``).
        index: 1-based test index within that technique's YAML file.

    Returns:
        The reviewed ``Label`` for this test.

    Raises:
        MissingLabelError: If no reviewed label exists for this test.
    """
    key = (technique, index)
    if key not in labels:
        msg = (
            f"no reviewed label for {technique}#{index}; add it to "
            "atomic_labels.yaml before converting"
        )
        raise MissingLabelError(msg)
    return labels[key]
