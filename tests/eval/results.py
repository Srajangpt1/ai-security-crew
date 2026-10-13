"""What a guard did with each case, and how a run is described."""

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

# Jev input price: $0.042 per million tokens (docs.typesafe.ai/models, Oct 2026).
USD_PER_INPUT_TOKEN = 0.042 / 1_000_000


class Result(BaseModel):
    """One guard decision. `action` is None when the case was not judged."""

    case_id: str
    trial: int = 0
    action: str | None = None
    scores: dict[str, float] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)  # Jev answers, for sweeps
    confidence: float | None = None
    latency_ms: float | None = None
    input_tokens: int | None = None
    cost_usd: float | None = None
    model: str | None = None
    error: str | None = None


class RunMeta(BaseModel):
    """What was run, so a result can be reproduced and cited."""

    guard: str
    dataset: str
    dataset_revision: str
    date: str
    trials: int
    cases: int
    model: str | None = None
    thresholds: dict[str, float] = Field(default_factory=dict)


def write_results(path: Path, results: list[Result], meta: RunMeta) -> None:
    """Write results as JSON Lines plus `<path>.meta.json`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(r.model_dump_json(exclude_none=True) + "\n")
    meta_path = path.with_name(path.name + ".meta.json")
    meta_path.write_text(json.dumps(meta.model_dump(), indent=2) + "\n", "utf-8")


def read_results(path: Path) -> list[Result]:
    """Read a results file written by `write_results`."""
    lines = path.read_text("utf-8").splitlines()
    return [Result.model_validate_json(line) for line in lines if line.strip()]
