# Evaluating asc-guard

`tests/eval/` scores asc-guard against the cases in
[agent-guard-bench](https://github.com/Srajangpt1/agent-guard-bench). It is dev tooling: it is not part of the
installed package and not part of CI, because it needs `TYPESAFE_API_KEY` and makes real API calls (about
$0.00002 per case).

## Run it

```bash
git clone https://github.com/Srajangpt1/agent-guard-bench ../agent-guard-bench   # once
export TYPESAFE_API_KEY=...

uv run python -m tests.eval run --split dev --trials 3          # judge, save, print scores
uv run python -m tests.eval score results/asc-guard-<date>.jsonl # score a saved run
uv run python -m tests.eval sweep results/asc-guard-<date>.jsonl \
    --param allow_user_p --values 0.6,0.7,0.8,0.9               # try thresholds, no API calls
```

Useful options for `run`: `--cases` (folder or file; env `AGENT_GUARD_BENCH` names the repo), `--split`,
`--kind`, `--source`, `--limit`, `--trials`, `--workers`, `--guard always-allow|always-ask` for baselines.

## What it does

- **Adapter** (`adapter.py`): turns a case into what asc-guard sees in a real session. `attack` and `normal` cases
  become a before-tool-call event with the case's `user_messages` and `flagged_content` loaded into the session
  store; `result_scan` cases become an after-tool-result event (a flagged result is reported as `deny`).
  `config_change` cases are skipped until the ConfigChange hook exists.
- **Results** (`results.py`): one line per case and trial with the action, Jev's raw answers, confidence, latency,
  token usage and cost, plus `<file>.meta.json` with the guard, dataset revision, model and thresholds.
- **Scoring** (`scoring.py`): the metrics defined in the benchmark README, overall and per kind, category,
  source and split, with the min and max across trials.
- **Sweep** (`sweep.py`): re-applies the policy to the saved raw answers with a different threshold. Calls that
  never reached Jev (protected-file rule, read-only tools) keep their action.
- **Converters** (`convert/`): build cases from AgentDojo runs and Atomic Red Team tests; they write into the
  dataset repo.

## Reporting results

Record the dataset commit, the model version (`jev-1.13.0`, not the moving `jev-latest`), the number of
trials and the thresholds; `run` writes all of these to the meta file. Jev's scores vary a little from run to
run, so use several trials and report the spread.
