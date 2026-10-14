"""python -m tests.eval.live: run benchmark cases through real Claude Code sessions."""

import json
import shutil
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import click

from tests.eval.cases import load_cases
from tests.eval.live import judge, scenario, session


def _summary(rows: list[dict]) -> str:
    atk = [r for r in rows if r["kind"] == "attack"]
    ben = [r for r in rows if r["kind"] != "attack"]
    c = Counter(r["outcome"] for r in atk)
    tried = c["stopped"] + c["missed"]
    lines = [f"attack sessions {len(atk)}: {dict(c)}"]
    if tried:
        lines.append(
            f"  guard stopped {c['stopped']}/{tried} attempted attacks ({c['stopped'] / tried:.1%})"  # noqa: E501
        )
    if atk:
        lines.append(
            f"  agent tried the attack in {tried}/{len(atk)}; scan flagged the README in {sum(r['flagged'] for r in atk)}/{len(atk)}"  # noqa: E501
        )
    b = Counter(r["outcome"] for r in ben)
    lines.append(f"benign sessions {len(ben)}: {dict(b)}")
    return "\n".join(lines)


@click.command()
@click.option(
    "--cases",
    "cases_dir",
    type=click.Path(path_type=Path),
    default="../agent-guard-bench/data/cases",
)
@click.option("--model", default="haiku", show_default=True)
@click.option("--attacks", default=50, show_default=True)
@click.option("--benign", default=20, show_default=True)
@click.option("--repeats", default=3, show_default=True)
@click.option("--workers", default=6, show_default=True)
@click.option(
    "--style", type=click.Choice(["setup", "notes"]), default="setup", show_default=True
)
@click.option("--naive", is_flag=True, help="Tell the agent to follow project notes.")
@click.option("--out", type=click.Path(path_type=Path), default="live-results.jsonl")
def main(
    cases_dir: Path,
    model: str,
    attacks: int,
    benign: int,
    repeats: int,
    workers: int,
    style: str,
    naive: bool,  # noqa: FBT001
    out: Path,
) -> None:
    """Dry run: shell commands never execute; every guard decision is recorded."""
    guard = shutil.which("asc-guard") or ""
    if not guard:
        raise click.ClickException("asc-guard is not on PATH")
    cases = load_cases(cases_dir)
    chosen = scenario.pick(cases, "attack", attacks) + scenario.pick(
        cases, "normal", benign
    )
    jobs = [(c, r) for c in chosen for r in range(repeats)]
    root = Path(tempfile.mkdtemp(prefix="live-"))
    done = 0

    def work(job: tuple) -> dict:
        nonlocal done
        case, rep = job
        sub = root / f"r{rep}"
        sub.mkdir(exist_ok=True)
        row = session.run_case(case, sub, guard, model, naive=naive, style=style)
        res = {
            **judge.judge(case, row),
            "repeat": rep,
            "cost_usd": row.get("cost_usd"),
            "seconds": row["seconds"],
            "events": row["events"],
            "reply": row.get("reply"),
        }
        done += 1
        click.echo(f"[{done}/{len(jobs)}] {case.id} {res['outcome']}", err=True)
        return res

    with ThreadPoolExecutor(workers) as pool:
        rows = list(pool.map(work, jobs))
    out.write_text("".join(json.dumps(r) + "\n" for r in rows))
    click.echo(_summary(rows))
    click.echo(f"cost ${sum(r['cost_usd'] or 0 for r in rows):.2f}; results: {out}")


if __name__ == "__main__":
    main()
