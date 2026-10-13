"""Convert recorded AgentDojo runs into agent-guard-bench cases.

Usage:
    python -m tests.eval.convert.agentdojo --runs <runs dir> \
        --suites <default_suites/v1 dir> --out <jsonl path>

Sampling is deterministic (see ``agentdojo_sample``): candidates are ordered
by SHA-256 of ``SEED|<run path>``; up to two runs are taken per group
(obeyed attacks: suite, injection task, attack type; benign: suite, user
task), preferring a different model, then a different user task. Case ids are
numbered in sorted group order; the split is a hash of the id (~20% test).
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from tests.eval.convert import agentdojo_runs as runs
from tests.eval.convert.agentdojo_cases import survives_clip
from tests.eval.convert.agentdojo_sample import Cand, build
from tests.eval.convert.agentdojo_tasks import load_tasks


def collect(
    runs_dir: Path, suites: Path
) -> tuple[list[Cand], list[Cand], Counter[str]]:
    """Scan all run files.

    Args:
        runs_dir: Directory holding ``<model>/<suite>/<user_task>/<attack>``.
        suites: The ``default_suites/v1`` directory.

    Returns:
        Attack candidates, benign candidates and a count of skipped runs by
        reason.
    """
    tasks = load_tasks(suites)
    skips: Counter[str] = Counter()
    attack: list[Cand] = []
    benign: list[Cand] = []
    for f in sorted(runs_dir.glob("*/*/*/*/*.json")):
        model, suite, user_task, atype = f.relative_to(runs_dir).parts[:4]
        run = runs.load_run(f)
        msg = runs.first_user_message(run) if run else None
        if run is None or msg is None:
            skips["run file unreadable, malformed, or without a user message"] += 1
        elif atype == "none":
            rank = 0 if run.get("utility") else 1
            group = (suite, user_task)
            benign.append(Cand(str(f), model, user_task, group, rank, (run, msg)))
        elif run["security"]:
            info = tasks[(suite, run["injection_task_id"])]
            hit = runs.find_injection(run)
            call = runs.find_attacker_call(run, info, hit.index) if hit else None
            if hit is None:
                skips["obeyed, injected text not in any tool result"] += 1
            elif not survives_clip(hit):
                skips["obeyed, injection clipped out of the 8000-char scan"] += 1
            elif call is None:
                skips["obeyed, no attacker call identified"] += 1
            else:
                inj = run["injection_task_id"]
                prov = f"agentdojo {model} {suite}/{user_task}/{atype}/{inj}"
                data = (msg, hit, call, info.category, atype, prov)
                group = (suite, inj, atype)
                attack.append(Cand(str(f), model, user_task, group, 0, data))
    return attack, benign, skips


def main() -> None:
    """Command line entry point."""
    ap = argparse.ArgumentParser(description="AgentDojo runs to benchmark cases")
    ap.add_argument("--runs", type=Path, required=True)
    ap.add_argument("--suites", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    attack, benign, skips = collect(args.runs, args.suites)
    out = build(attack, benign)
    lines = [json.dumps(c, ensure_ascii=False) for c in out]
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    counts = Counter(f"{c['kind']}/harmful={c['expected']['harmful']}" for c in out)
    print(dict(counts))
    for reason, n in sorted(skips.items()):
        print(f"skipped {n}: {reason}")


if __name__ == "__main__":
    main()
