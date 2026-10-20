"""Run, score and sweep: `python -m tests.eval --help`."""

import datetime
import json
import os
import sys
from pathlib import Path

import click

from tests.eval.adapter import get_guard
from tests.eval.cases import dataset_revision, load_cases
from tests.eval.results import RunMeta, read_results, write_results
from tests.eval.runner import run as run_cases
from tests.eval.scoring import format_report, score
from tests.eval.sweep import format_sweep, sweep

DEFAULT_CASES = (
    Path(os.environ.get("AGENT_GUARD_BENCH", "../agent-guard-bench")) / "data" / "cases"
)
CASES = click.option(
    "--cases",
    "cases_path",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_CASES,
    show_default=True,
    help="Folder of .jsonl cases (env AGENT_GUARD_BENCH names the repo).",
)


def filters(f):  # type: ignore[no-untyped-def]
    """Add --split, --kind and --source to a command."""
    for name in ("source", "kind", "split"):
        f = click.option(f"--{name}", multiple=True, help=f"Only these {name}s.")(f)
    return f


@click.group()
def main() -> None:
    """Evaluate asc-guard against agent-guard-bench cases."""


@main.command()
@click.option("--guard", "guard_name", default="asc-guard", show_default=True)
@CASES
@click.option("--split", multiple=True, help="Only these splits (repeatable).")
@click.option("--kind", multiple=True, help="Only these kinds (repeatable).")
@click.option("--source", multiple=True, help="Only these sources (repeatable).")
@click.option("--limit", type=int, default=0, help="Only the first N cases.")
@click.option("--trials", type=int, default=1, show_default=True)
@click.option("--workers", type=int, default=8, show_default=True)
@click.option("--out", type=click.Path(path_type=Path), default=None)
def run(
    guard_name: str,
    cases_path: Path,
    split: tuple[str, ...],
    kind: tuple[str, ...],
    source: tuple[str, ...],
    limit: int,
    trials: int,
    workers: int,
    out: Path | None,
) -> None:
    """Judge the cases, save results, print the scores."""
    try:
        guard = get_guard(guard_name)
        cases = load_cases(cases_path, split, kind, source, limit)
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"{len(cases)} cases x {trials} trials, {workers} workers", err=True)
    show = sys.stderr.isatty()
    results = run_cases(
        cases,
        guard,
        trials,
        workers,
        on_done=(lambda i, n: click.echo(f"\r{i}/{n}", nl=False, err=True))
        if show
        else None,
    )
    if show:
        click.echo("", err=True)
    thresholds = getattr(getattr(guard, "thresholds", None), "__dict__", {})
    meta = RunMeta(
        guard=guard.name,
        dataset=str(cases_path),
        dataset_revision=dataset_revision(cases_path),
        date=datetime.datetime.now(datetime.UTC).date().isoformat(),
        trials=trials,
        cases=len(cases),
        thresholds={k: float(v) for k, v in thresholds.items()},
        model=next((r.model for r in results if r.model), None),
    )
    out = out or Path("results") / f"{guard.name}-{meta.date}.jsonl"
    write_results(out, results, meta)
    click.echo(format_report(score(cases, results)))
    click.echo(f"results: {out}  (model {meta.model}, dataset {meta.dataset_revision})")


@main.command("score")
@click.argument("results", type=click.Path(exists=True, path_type=Path))
@CASES
@filters
@click.option("--json", "as_json", is_flag=True, help="Print the full report.")
def score_cmd(  # noqa: PLR0913
    results: Path,
    cases_path: Path,
    split: tuple[str, ...],
    kind: tuple[str, ...],
    source: tuple[str, ...],
    as_json: bool,  # noqa: FBT001
) -> None:
    """Score a results file, optionally only some splits, kinds or sources."""
    cases = load_cases(cases_path, split, kind, source)
    report = score(cases, read_results(results))
    click.echo(json.dumps(report, indent=2) if as_json else format_report(report))


@main.command("sweep")
@click.argument("results", type=click.Path(exists=True, path_type=Path))
@CASES
@filters
@click.option("--param", required=True, help="A threshold name, e.g. allow_user_p.")
@click.option("--values", required=True, help="Comma-separated values to try.")
def sweep_cmd(  # noqa: PLR0913
    results: Path,
    cases_path: Path,
    split: tuple[str, ...],
    kind: tuple[str, ...],
    source: tuple[str, ...],
    param: str,
    values: str,
) -> None:
    """Re-apply the policy to saved answers with other thresholds."""
    try:
        rows = sweep(
            load_cases(cases_path, split, kind, source),
            read_results(results),
            param,
            [float(v) for v in values.split(",")],
        )
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    click.echo(format_sweep(param, rows))
