"""Convert Atomic Red Team Linux shell tests into agent-guard-bench cases.

Usage:
    python -m tests.eval.convert.atomic --atomics <atomics dir> --out <jsonl path>
"""

import argparse
import hashlib
import json
from pathlib import Path

from tests.eval.convert.atomic_cases import (
    attack_with_injection,
    attack_without_injection,
)
from tests.eval.convert.atomic_cases_other import normal_case, result_scan_case
from tests.eval.convert.atomic_extract import extract
from tests.eval.convert.atomic_labels import load_labels, require_label

LABELS_PATH = Path(__file__).parent / "atomic_labels.yaml"


def _scan_sample(key: str) -> bool:
    """Tell whether a harmful test is in the ~1/3 result_scan sample.

    Args:
        key: Stable text identifying the test (``technique#index``).

    Returns:
        True for about a third of inputs, chosen by a stable hash.
    """
    digest = hashlib.sha256((key + "|scan-sample").encode("utf-8")).hexdigest()
    return int(digest, 16) % 3 == 0


def convert(atomics: Path, labels_path: Path = LABELS_PATH) -> list[dict]:
    """Run the full extract -> label -> emit pipeline.

    Args:
        atomics: The Atomic Red Team ``atomics`` directory.
        labels_path: Path to the reviewed ``atomic_labels.yaml`` file.

    Returns:
        All generated case dicts, in deterministic order.

    Raises:
        MissingLabelError: If any usable test has no reviewed label.
    """
    extraction = extract(atomics)
    labels = load_labels(labels_path)

    cases: list[dict] = []
    atk_n = scn_n = nrm_n = 0
    dropped_no_context = 0
    for test in extraction.tests:
        label = require_label(labels, test.technique, test.index)
        key = f"{test.technique}#{test.index}"
        if label.label == "HARMFUL":
            atk_n += 1
            with_case = attack_with_injection(f"atm-atk-{atk_n:04d}", test, label)
            cases.append(with_case)
            if label.context_dependent:
                dropped_no_context += 1
            else:
                atk_n += 1
                case_b = f"atm-atk-{atk_n:04d}"
                user_message = with_case["user_messages"][0]
                cases.append(
                    attack_without_injection(case_b, test, label, user_message)
                )
            if _scan_sample(key):
                scn_n += 1
                cases.append(result_scan_case(f"atm-scn-{scn_n:04d}", test, label))
        else:
            nrm_n += 1
            cases.append(normal_case(f"atm-nrm-{nrm_n:04d}", test, label))

    print(
        f"dropped {len(extraction.unresolved)} unresolved-placeholder tests, "
        f"{len(extraction.too_long)} over-length tests "
        f"(of {extraction.total} total linux sh/bash tests); "
        f"dropped {dropped_no_context} no-context attack variants "
        "(context_dependent)"
    )
    return cases


def write_jsonl(cases: list[dict], out_path: Path) -> None:
    """Write ``cases`` as one JSON object per line, UTF-8, sorted by id.

    Args:
        cases: Case dicts to write.
        out_path: Destination ``.jsonl`` file.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps(case, ensure_ascii=False, sort_keys=True)
        for case in sorted(cases, key=lambda case: case["id"])
    ]
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--atomics", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    cases = convert(args.atomics)
    write_jsonl(cases, args.out)
    print(f"wrote {len(cases)} cases to {args.out}")


if __name__ == "__main__":
    main()
