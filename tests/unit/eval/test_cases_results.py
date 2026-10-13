"""Loading cases and writing results."""

import json
from pathlib import Path

import pytest

from tests.eval.cases import load_cases
from tests.eval.results import Result, RunMeta, read_results, write_results
from tests.unit.eval.conftest import make_case


def write_cases(path: Path, *cases: dict) -> Path:
    path.write_text("\n".join(json.dumps(c) for c in cases) + "\n")
    return path


def line(id: str = "a", **extra: object) -> dict:
    case = make_case(id).model_dump()
    case.update(extra)
    return case


def test_load_and_filter(tmp_path: Path) -> None:
    path = write_cases(
        tmp_path / "x.jsonl",
        line("a"),
        line("b", split="test"),
        line("c", source="agentdojo"),
    )
    assert [c.id for c in load_cases(path)] == ["a", "b", "c"]
    assert [c.id for c in load_cases(path, splits=("test",))] == ["b"]
    assert [c.id for c in load_cases(path, sources=("agentdojo",))] == ["c"]
    assert len(load_cases(path, limit=2)) == 2


def test_folder_loading_and_duplicates(tmp_path: Path) -> None:
    write_cases(tmp_path / "a.jsonl", line("a"))
    write_cases(tmp_path / "b.jsonl", line("a"))
    with pytest.raises(ValueError, match="duplicate"):
        load_cases(tmp_path)


def test_bad_line_names_file_and_number(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text('{"id": "x"}\n')
    with pytest.raises(ValueError, match=r"bad\.jsonl:1"):
        load_cases(path)


def test_unknown_fields_are_rejected(tmp_path: Path) -> None:
    path = write_cases(tmp_path / "x.jsonl", line("a", surprise=1))
    with pytest.raises(ValueError, match="surprise"):
        load_cases(path)


def test_results_round_trip_with_unjudged_cases(tmp_path: Path) -> None:
    out = tmp_path / "r" / "run.jsonl"
    meta = RunMeta(
        guard="g",
        dataset="d",
        dataset_revision="abc",
        date="2026-10-13",
        trials=1,
        cases=2,
    )
    write_results(
        out,
        [
            Result(case_id="a", action="deny", raw={"x": {"noul": 1.0}}),
            Result(case_id="b", error="boom"),
        ],
        meta,
    )
    loaded = read_results(out)
    assert loaded[0].raw == {"x": {"noul": 1.0}}
    assert loaded[1].action is None and loaded[1].error == "boom"
    assert (
        json.loads(Path(str(out) + ".meta.json").read_text())["dataset_revision"]
        == "abc"
    )


def test_the_real_seed_cases_load() -> None:
    seed = Path("/home/user/agent-guard-bench/data/cases/seed.jsonl")
    if not seed.exists():
        pytest.skip("agent-guard-bench is not checked out")
    assert len(load_cases(seed)) >= 60
