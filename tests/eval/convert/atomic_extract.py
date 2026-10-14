"""Extract Linux shell commands from Atomic Red Team YAML files."""

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from tests.eval.convert.atomic_sanitize import sanitize

PLACEHOLDER = re.compile(r"#\{([^}]+)\}")
MAX_LEN = 800


@dataclass
class AtomicTest:
    """One usable Atomic Red Team shell test."""

    technique: str
    index: int
    name: str
    command: str
    csv_tactic: str = ""
    elevation: bool = False


@dataclass
class Extraction:
    """Result of scanning the atomics directory."""

    tests: list[AtomicTest] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    too_long: list[str] = field(default_factory=list)
    total: int = 0


def load_tactics(atomics: Path) -> dict[tuple[str, int], str]:
    """Map (technique, test number) to the first tactic in the Linux index.

    Args:
        atomics: The ``atomics`` directory.

    Returns:
        Mapping used only as a hint when reviewing labels.
    """
    path = atomics / "Indexes" / "Indexes-CSV" / "linux-index.csv"
    out: dict[tuple[str, int], str] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            key = (row["Technique #"], int(row["Test #"]))
            out.setdefault(key, row["Tactic"])
    return out


def _substitute(command: str, args: dict) -> str | None:
    """Fill ``#{name}`` placeholders from defaults, or return None."""
    missing = False

    def repl(match: re.Match[str]) -> str:
        nonlocal missing
        arg = args.get(match.group(1))
        if not isinstance(arg, dict) or arg.get("default") is None:
            missing = True
            return match.group(0)
        return str(arg["default"])

    out = PLACEHOLDER.sub(repl, command)
    return None if missing else out


def extract(atomics: Path) -> Extraction:
    """Read every Linux sh/bash test, substitute defaults and sanitize.

    Args:
        atomics: The ``atomics`` directory.

    Returns:
        Extracted tests sorted by technique and index, plus drop counts.
    """
    result = Extraction()
    tactics = load_tactics(atomics)
    for path in sorted(atomics.glob("T*/T*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        technique = str(data.get("attack_technique", path.stem))
        for number, test in enumerate(data.get("atomic_tests") or [], 1):
            ex = test.get("executor") or {}
            raw = ex.get("command") or ""
            if "linux" not in test.get("supported_platforms", []):
                continue
            if ex.get("name") not in ("sh", "bash") or not raw.strip():
                continue
            result.total += 1
            label = f"{technique}#{number}"
            command = _substitute(raw, test.get("input_arguments") or {})
            if command is None:
                result.unresolved.append(label)
                continue
            command = sanitize(command.strip())
            if len(command) > MAX_LEN:
                result.too_long.append(label)
                continue
            result.tests.append(
                AtomicTest(
                    technique,
                    number,
                    str(test.get("name", "")),
                    command,
                    tactics.get((technique, number), ""),
                    bool(ex.get("elevation_required")),
                )
            )
    return result
