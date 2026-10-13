"""Load benchmark cases (JSON Lines) from a local copy of agent-guard-bench."""

import subprocess
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Expected(BaseModel):
    """The label: harmful or not, and which guard actions count as correct."""

    harmful: bool
    acceptable: list[str]


class Case(BaseModel):
    """One thing a guard must judge. Nothing in a case is ever executed."""

    model_config = ConfigDict(extra="forbid")

    id: str
    split: str = "dev"
    kind: str
    category: str
    source: str
    technique: str | None = None
    user_messages: list[str] = Field(default_factory=list)
    flagged_content: list[str] = Field(default_factory=list)
    carrier: dict[str, str] = Field(default_factory=dict)
    tool: str
    tool_input: dict[str, Any] = Field(default_factory=dict)
    tool_output: str | None = None
    expected: Expected
    notes: str = ""


def load_cases(
    path: Path,
    splits: tuple[str, ...] = (),
    kinds: tuple[str, ...] = (),
    sources: tuple[str, ...] = (),
    limit: int = 0,
) -> list[Case]:
    """Load cases from a .jsonl file or every .jsonl file in a folder.

    Args:
        path: A file or a folder of .jsonl files.
        splits: Keep only these splits (empty keeps all).
        kinds: Keep only these kinds.
        sources: Keep only these sources.
        limit: Keep only the first N cases after filtering (0 keeps all).

    Raises:
        ValueError: On an invalid case or a duplicate id.
    """
    files = sorted(path.glob("*.jsonl")) if path.is_dir() else [path]
    cases: list[Case] = []
    seen: set[str] = set()
    for file in files:
        for number, line in enumerate(file.read_text("utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                case = Case.model_validate_json(line)
            except ValueError as e:
                message = f"{file}:{number}: {e}"
                raise ValueError(message) from e
            if case.id in seen:
                message = f"duplicate case id: {case.id}"
                raise ValueError(message)
            seen.add(case.id)
            cases.append(case)
    keep = [
        c
        for c in cases
        if (not splits or c.split in splits)
        and (not kinds or c.kind in kinds)
        and (not sources or c.source in sources)
    ]
    return keep[:limit] if limit else keep


def dataset_revision(path: Path) -> str:
    """The git commit of the dataset folder, or "unknown" outside a git repo."""
    folder = path if path.is_dir() else path.parent
    try:
        out = subprocess.run(
            ["git", "-C", str(folder), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return out.stdout.strip() or "unknown"
