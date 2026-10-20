"""Tests for the read-only project scanner behind general_project_context."""

import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

from mcp_security_review.guard.clip import OMITTED
from mcp_security_review.security import project_context
from mcp_security_review.security.project_context import (
    MAX_FILE_BYTES,
    MAX_FILES,
    PathOutsideProjectError,
    ProjectPathNotFoundError,
    resolve_project_path,
    scan_project,
)
from tests.conftest import STACK50_SHA, make_stack50


def _strings(value: Any) -> list[str]:
    """Every string in a JSON-like value, keys included."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*_strings(k), *_strings(v))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


@pytest.fixture(params=["fwalk", "walk"])
def walk_mode(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Run a test with `os.fwalk` (POSIX) and with the `os.walk` fallback."""
    if request.param == "walk":
        monkeypatch.setattr(project_context, "_HAS_FWALK", False)

        def no_fwalk(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("os.fwalk used in the fallback")

        monkeypatch.setattr(os, "fwalk", no_fwalk, raising=False)
    elif not hasattr(os, "fwalk"):
        pytest.skip("os.fwalk is not available on this platform")
    return str(request.param)


@pytest.fixture
def stack(tmp_path: Path) -> Path:
    return make_stack50(tmp_path / "stack50")


def _line_of(path: Path, needle: str) -> int:
    lines = path.read_text(encoding="utf-8").splitlines()
    return next(i for i, line in enumerate(lines, start=1) if needle in line)


# ---- detection ----


@pytest.mark.usefixtures("walk_mode")
def test_detects_the_stack(stack: Path) -> None:
    ctx = scan_project(stack)

    assert {"python", "javascript"} <= set(ctx.languages)
    assert {"fastapi", "express", "ejs", "sqlalchemy", "psycopg"} <= set(ctx.frameworks)
    assert ctx.iac["terraform_providers"] == ["aws"]
    assert ctx.iac["dockerfiles"] == ["Dockerfile"]
    assert ctx.iac["compose"] == ["docker-compose.yml"]
    assert ctx.iac["kubernetes"] == []
    assert ctx.ci == ["github-actions"]
    assert {"semgrep", "trivy"} <= set(ctx.ci_scanners)
    assert ctx.truncated is False


@pytest.mark.usefixtures("walk_mode")
def test_flags_unpinned_action_with_its_line(stack: Path) -> None:
    ctx = scan_project(stack)

    workflow = stack / ".github" / "workflows" / "ci.yml"
    assert {
        "kind": "unpinned_action",
        "file": ".github/workflows/ci.yml",
        "line": _line_of(workflow, "actions/checkout@v4"),
        "ref": "actions/checkout@v4",
        "fix_with": "sca_verify_packages",
    } in ctx.flags


@pytest.mark.usefixtures("walk_mode")
def test_sha_pinned_steps_are_not_flagged(stack: Path) -> None:
    ctx = scan_project(stack)

    assert not [f for f in ctx.flags if STACK50_SHA in f["ref"]]
    assert not [f for f in ctx.flags if f["file"].endswith("semgrep.yml")]


@pytest.mark.usefixtures("walk_mode")
def test_flags_mutable_image_but_not_build_stages(stack: Path) -> None:
    ctx = scan_project(stack)

    images = [f for f in ctx.flags if f["kind"] == "mutable_image"]
    assert images == [
        {
            "kind": "mutable_image",
            "file": "Dockerfile",
            "line": 1,
            "ref": "python:3.12-slim",
            "fix_with": "sca_verify_packages",
        }
    ]


@pytest.mark.usefixtures("walk_mode")
def test_flags_module_without_version(stack: Path) -> None:
    ctx = scan_project(stack)

    modules = [f for f in ctx.flags if f["kind"] == "unpinned_module"]
    assert modules == [
        {
            "kind": "unpinned_module",
            "file": "infra/main.tf",
            "line": _line_of(stack / "infra" / "main.tf", "terraform-aws-modules"),
            "ref": "terraform-aws-modules/vpc/aws",
            "fix_with": "sca_verify_packages",
        }
    ]


def test_pinned_modules_and_digests_are_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'module "a" {\n'
        '  source  = "terraform-aws-modules/vpc/aws"\n'
        '  version = "5.8.1"\n'
        "}\n"
        'module "b" {\n'
        f'  source = "git::https://github.com/o/m.git?ref={STACK50_SHA}"\n'
        "}\n"
        'module "c" {\n'
        '  source = "./modules/local"\n'
        "}\n"
        'module "d" {\n'
        '  source = "git::https://github.com/o/m.git?ref=v1.2.0"\n'
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM scratch\nFROM alpine@sha256:" + "a" * 64 + "\n", encoding="utf-8"
    )

    ctx = scan_project(tmp_path)

    assert [(f["kind"], f["line"]) for f in ctx.flags] == [("unpinned_module", 12)]


def test_local_and_digest_actions_are_not_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "w.yml").write_text(
        "jobs:\n"
        "  a:\n"
        "    steps:\n"
        "      - uses: ./.github/actions/local\n"
        "      - uses: docker://alpine@sha256:" + "b" * 64 + "\n"
        "      - uses: docker://alpine:3\n"
        "      - run: |\n"
        "          uses: not/an-action@main\n"
        "  b:\n"
        "    uses: org/repo/.github/workflows/x.yml@main\n",
        encoding="utf-8",
    )

    ctx = scan_project(tmp_path)

    assert [(f["ref"], f["line"]) for f in ctx.flags] == [
        ("docker://alpine:3", 6),
        ("org/repo/.github/workflows/x.yml@main", 10),
    ]


def test_invalid_workflow_yaml_falls_back_to_line_matching(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "w.yml").write_text(
        "jobs: [\n      - uses: actions/setup-node@v4\n", encoding="utf-8"
    )

    ctx = scan_project(tmp_path)

    assert [(f["ref"], f["line"]) for f in ctx.flags] == [("actions/setup-node@v4", 2)]


def test_detects_kubernetes_and_helm(tmp_path: Path) -> None:
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "app.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\n", encoding="utf-8"
    )
    (tmp_path / "deploy" / "values.yaml").write_text("replicas: 2\n", encoding="utf-8")
    (tmp_path / "chart").mkdir()
    (tmp_path / "chart" / "Chart.yaml").write_text(
        "apiVersion: v2\nname: app\n", encoding="utf-8"
    )

    ctx = scan_project(tmp_path)

    assert ctx.iac["kubernetes"] == ["deploy/app.yaml"]
    assert ctx.iac["helm"] == ["chart/Chart.yaml"]
    assert "kubernetes" in ctx.suggested_components


@pytest.mark.usefixtures("walk_mode")
def test_reads_existing_threat_model_headings(stack: Path) -> None:
    ctx = scan_project(stack)

    assert ctx.existing_threat_model == {
        "path": "threat-model.md",
        "headings": ["Assets", "Threats"],
    }


# ---- suggestions ----


@pytest.mark.usefixtures("walk_mode")
def test_suggests_components_for_the_stack(stack: Path) -> None:
    ctx = scan_project(stack)

    assert {
        "cloud-compute",
        "cloud-network",
        "cloud-iam",
        "cloud-encryption-and-logging",
        "container-image",
        "ci-pipeline",
        "web-endpoint",
        "database",
    } <= set(ctx.suggested_components)
    assert "cloud-storage" not in ctx.suggested_components
    assert "kubernetes" not in ctx.suggested_components


def test_storage_and_database_resources_add_components(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'resource "google_storage_bucket" "b" {}\n'
        'resource "google_sql_database_instance" "d" {}\n',
        encoding="utf-8",
    )

    ctx = scan_project(tmp_path)

    assert ctx.iac["terraform_providers"] == ["google"]
    assert {"cloud-storage", "cloud-data-store"} <= set(ctx.suggested_components)


def test_suggestions_only_use_known_components(stack: Path) -> None:
    ctx = scan_project(stack, known_components={"web-endpoint", "ci-pipeline"})

    assert ctx.suggested_components == ["web-endpoint", "ci-pipeline"]


# ---- boundaries ----


@pytest.mark.usefixtures("walk_mode")
def test_sensitive_files_are_listed_never_read(
    stack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("server.pem", "id_rsa", "prod.tfvars", "terraform.tfstate"):
        (stack / "infra" / name).write_text("do-not-read\n", encoding="utf-8")
    opened: list[str] = []
    real_open = os.open

    def recording_open(path: Any, *args: Any, **kwargs: Any) -> int:
        opened.append(os.fspath(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)

    ctx = scan_project(stack)

    assert ctx.sensitive_files_present == [
        ".env",
        "infra/id_rsa",
        "infra/prod.tfvars",
        "infra/server.pem",
        "infra/terraform.tfstate",
    ]
    assert opened, "files are read through os.open"
    sensitive = {".env", "server.pem", "id_rsa", "prod.tfvars", "terraform.tfstate"}
    assert not [p for p in opened if Path(p).name in sensitive]
    assert "do-not-read" not in json.dumps(ctx.to_dict())


@pytest.mark.usefixtures("walk_mode")
def test_symlinks_are_not_followed(stack: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Dockerfile").write_text("FROM evil:latest\n", encoding="utf-8")
    (outside / "evil.tf").write_text(
        'resource "google_storage_bucket" "b" {}\n', encoding="utf-8"
    )
    (stack / "infra" / "link").symlink_to("/etc")
    (stack / "infra" / "outside").symlink_to(outside)
    (stack / "infra" / "evil.tf").symlink_to(outside / "evil.tf")
    (stack / "Dockerfile.evil").symlink_to(outside / "Dockerfile")

    ctx = scan_project(stack)

    text = json.dumps(ctx.to_dict())
    assert "infra/link" not in text and "infra/outside" not in text
    assert "evil" not in text
    assert ctx.iac["terraform_providers"] == ["aws"]


@pytest.mark.usefixtures("walk_mode")
def test_huge_trees_are_truncated(tmp_path: Path) -> None:
    for i in range(MAX_FILES + 1000):
        (tmp_path / f"f{i}.txt").write_bytes(b"")

    ctx = scan_project(tmp_path)

    assert ctx.truncated is True


def test_long_workflow_lines_are_clipped(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "big.yml").write_text(
        "jobs:\n  a:\n    steps:\n      - uses: evil/act@" + "A\x1b" * 500_000 + "\n",
        encoding="utf-8",
    )

    ctx = scan_project(tmp_path)

    strings = _strings(ctx.to_dict())
    assert ctx.flags and ctx.flags[0]["kind"] == "unpinned_action"
    assert max(len(s) for s in strings) <= 200 + len(OMITTED)
    assert not [s for s in strings if "\x1b" in s]
    assert ctx.truncated is True


def test_pathological_files_scan_quickly(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("a" * 200_000 + "\n", encoding="utf-8")
    (tmp_path / "threat-model.md").write_text(
        "## x" + " " * 200_000 + "y\n", encoding="utf-8"
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM" + " " * 200_000 + "x\n", encoding="utf-8"
    )

    start = time.monotonic()
    ctx = scan_project(tmp_path)

    assert time.monotonic() - start < 5
    assert ctx.existing_threat_model is not None
    assert len(ctx.existing_threat_model["headings"][0]) <= 200 + len(OMITTED)


@pytest.mark.parametrize(
    "body", ["\n" * MAX_FILE_BYTES, " \n" * (MAX_FILE_BYTES // 2)], ids=["nl", "sp-nl"]
)
def test_blank_line_floods_scan_quickly(tmp_path: Path, body: str) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (tmp_path / "main.tf").write_text(body, encoding="utf-8")
    (workflows / "w.yml").write_text(body, encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(body, encoding="utf-8")
    (tmp_path / "app.yaml").write_text(body, encoding="utf-8")

    start = time.monotonic()
    ctx = scan_project(tmp_path)

    assert time.monotonic() - start < 10
    assert ctx.flags == []


def test_flow_style_steps_are_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "w.yml").write_text(
        "jobs:\n"
        "  a:\n"
        "    steps:\n"
        "      - {uses: actions/checkout@v4}\n"
        "      - {name: setup, uses: 'actions/setup-node@v4', with: {x: 1}}\n",
        encoding="utf-8",
    )

    ctx = scan_project(tmp_path)

    assert [(f["ref"], f["line"]) for f in ctx.flags] == [
        ("actions/checkout@v4", 4),
        ("actions/setup-node@v4", 5),
    ]


def test_uppercase_sha_counts_as_pinned(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "w.yml").write_text(
        "jobs:\n  a:\n    steps:\n"
        f"      - uses: actions/checkout@{STACK50_SHA.upper()}\n",
        encoding="utf-8",
    )

    assert scan_project(tmp_path).flags == []


def test_special_files_are_skipped_without_blocking(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "Dockerfile")

    ctx = scan_project(tmp_path)

    assert ctx.iac["dockerfiles"] == []


def test_flags_are_capped(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "".join(f"FROM img{i}:latest\n" for i in range(80)), encoding="utf-8"
    )

    ctx = scan_project(tmp_path)

    assert len(ctx.flags) == 50
    assert ctx.truncated is True


# ---- path resolution ----


def test_resolve_accepts_paths_inside_cwd(stack: Path) -> None:
    assert resolve_project_path("", stack) == stack.resolve()
    assert resolve_project_path("infra", stack) == (stack / "infra").resolve()
    assert resolve_project_path(str(stack / "api"), stack) == (stack / "api").resolve()


@pytest.mark.parametrize("path", ["../..", "/etc", "infra/../../.."])
def test_resolve_rejects_paths_outside_cwd(stack: Path, path: str) -> None:
    with pytest.raises(PathOutsideProjectError):
        resolve_project_path(path, stack)


def test_resolve_rejects_symlink_pointing_outside(stack: Path) -> None:
    (stack / "infra" / "link").symlink_to("/etc")

    with pytest.raises(PathOutsideProjectError):
        resolve_project_path("infra/link", stack)


def test_resolve_rejects_missing_and_file_paths(stack: Path) -> None:
    with pytest.raises(ProjectPathNotFoundError):
        resolve_project_path("nope", stack)
    with pytest.raises(ProjectPathNotFoundError):
        resolve_project_path("Dockerfile", stack)
