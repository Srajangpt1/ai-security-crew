"""Run a guard over cases, several trials, several threads at a time."""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from tests.eval.adapter import Guard
from tests.eval.cases import Case
from tests.eval.results import Result


def _one(guard: Guard, case: Case, trial: int) -> Result:
    if not guard.supports(case):
        return Result(case_id=case.id, trial=trial)
    try:
        return guard.judge(case, trial)
    except (RuntimeError, ValueError, OSError) as e:
        return Result(case_id=case.id, trial=trial, error=str(e))


def run(
    cases: list[Case],
    guard: Guard,
    trials: int = 1,
    workers: int = 8,
    on_done: Callable[[int, int], None] | None = None,
) -> list[Result]:
    """Judge every case `trials` times. A failing case is recorded, not fatal.

    Results come back in case order, then trial order, whatever the thread
    timing was.
    """
    jobs = [(case, trial) for case in cases for trial in range(trials)]
    results: list[Result | None] = [None] * len(jobs)

    def work(index: int) -> None:
        results[index] = _one(guard, *jobs[index])
        if on_done:
            on_done(sum(r is not None for r in results), len(jobs))

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(pool.map(work, range(len(jobs))))
    return [r for r in results if r is not None]
