"""Tests for the two-call lightweight_security_review tool."""

import json
from pathlib import Path
from textwrap import dedent
from typing import Any

import pytest
from fastmcp import Client

from mcp_security_review.guard.clip import OMITTED
from mcp_security_review.providers.attack import PENDING_STATUS
from mcp_security_review.servers.main import main_mcp
from tests.conftest import make_stack50

TOOL = "general_lightweight_security_review"


async def call(**args: Any) -> dict[str, Any]:
    async with Client(main_mcp) as client:
        result = await client.call_tool(TOOL, args)
    items = result if isinstance(result, list) else result.content
    return json.loads(items[0].text)


@pytest.mark.anyio
async def test_first_call_returns_component_menu() -> None:
    data = await call(task_description="Add avatar upload to my Flask app")

    assert data["status"] == "needs_components"
    ids = [c["id"] for c in data["components"]]
    assert "file-upload" in ids and "database" in ids
    assert all(c["applies_when"] for c in data["components"])
    assert "credentials" in data["data_handled_options"]
    assert len(json.dumps(data)) < 8000


@pytest.mark.anyio
async def test_second_call_returns_threats_and_countermeasures() -> None:
    data = await call(
        task_description="Add avatar upload to my Flask app",
        components="file-upload, object-storage",
        technologies="Python, Flask, S3",
    )

    assert data["success"] is True
    assert data["status"] == "complete"
    assessment = data["assessment"]
    assert assessment["risk_level"] == "high"
    assert assessment["components"] == ["file-upload", "object-storage"]
    assert assessment["implied_components"] == ["web-endpoint"]
    threat_ids = {t["id"] for t in assessment["threats"]}
    assert {"upload-executable-file", "public-bucket"} <= threat_ids
    assert data["technologies"] == ["Python", "Flask", "S3"]

    cm = {m["id"]: m for m in assessment["countermeasures"]}
    assert "upload-rename-and-isolate" in cm
    assert cm["upload-rename-and-isolate"]["asvs"]
    assert cm["upload-rename-and-isolate"]["mitigates"]
    # Every mitigated threat id is one of the returned threats.
    for measure in cm.values():
        assert set(measure["mitigates"]) <= threat_ids


@pytest.mark.anyio
async def test_implied_threats_are_secondary_and_capped() -> None:
    data = await call(task_description="Upload", components="file-upload")

    assessment = data["assessment"]
    assert "csrf" not in {t["id"] for t in assessment["threats"]}
    assert "csrf" in {t["id"] for t in assessment["also_consider"]}
    assert len(assessment["also_consider"]) <= 8
    assert assessment["also_consider_total"] >= len(assessment["also_consider"])


@pytest.mark.anyio
async def test_agent_threats_carry_mcp_top10_ids_and_others_do_not() -> None:
    data = await call(task_description="Add an AI agent", components="llm-integration")
    threats = {t["id"]: t for t in data["assessment"]["threats"]}

    assert threats["prompt-injection"]["mcp_top10"] == ["MCP06:2025"]

    data = await call(task_description="Query", components="database")
    sql = next(t for t in data["assessment"]["threats"] if t["id"] == "sql-injection")
    assert "mcp_top10" not in sql


@pytest.mark.anyio
async def test_menu_tells_the_agent_to_pick_only_what_changes() -> None:
    data = await call(task_description="Add avatar upload")

    assert "adds or directly modifies" in data["instructions"]
    assert "generously" not in data["instructions"]


@pytest.mark.anyio
async def test_picking_many_components_adds_a_narrowing_hint() -> None:
    narrow = await call(task_description="x", components="file-upload,object-storage")
    broad = await call(
        task_description="x",
        components=(
            "web-endpoint,authentication,session-management,authorization,database,"
            "file-upload,object-storage"
        ),
    )

    assert narrow["hint"] is None
    assert "7 components" in broad["hint"]


@pytest.mark.anyio
async def test_alias_counts_as_one_pick_for_the_narrowing_hint() -> None:
    data = await call(task_description="x", components="container-and-iac")

    assert len(data["assessment"]["components"]) > 6
    assert data["hint"] is None


@pytest.mark.anyio
async def test_sensitive_data_raises_the_risk_level() -> None:
    plain = await call(task_description="Upload", components="file-upload")
    sensitive = await call(
        task_description="Upload",
        components="file-upload",
        data_handled="personal_data",
    )

    assert plain["assessment"]["risk_level"] == "high"
    assert sensitive["assessment"]["risk_level"] == "critical"
    assert sensitive["assessment"]["sensitive_data"] == ["personal_data"]


@pytest.mark.anyio
async def test_component_ids_tolerate_case_and_underscores() -> None:
    data = await call(task_description="x", components="File_Upload, OBJECT_STORAGE")

    assert data["success"] is True
    assert data["assessment"]["components"] == ["file-upload", "object-storage"]


@pytest.mark.anyio
async def test_unknown_component_lists_valid_ids() -> None:
    data = await call(task_description="x", components="file-upload,teleporter")

    assert data["success"] is False
    assert data["error"]["code"] == "unknown_component"
    assert "teleporter" in data["error"]["message"]
    assert "file-upload" in data["valid_components"]


@pytest.mark.anyio
async def test_login_review_is_much_smaller_than_the_old_output() -> None:
    data = await call(
        task_description="Email and password login with JWT sessions",
        components="authentication,session-management,database",
        data_handled="credentials",
    )

    assert data["assessment"]["risk_level"] == "critical"
    # The previous guideline-based review of this task was about 52,000 characters.
    assert len(json.dumps(data, separators=(",", ":"))) < 16000


@pytest.mark.anyio
async def test_project_library_adds_custom_component(tmp_path: Path) -> None:
    folder = tmp_path / ".ai-security-crew" / "library"
    folder.mkdir(parents=True)
    (folder / "team.yaml").write_text(
        dedent(
            """
            components:
              - id: internal-sso
                name: Company SSO
                applies_when: The feature signs users in through our SSO.
            threats:
              - id: sso-token-reuse
                name: A token for one app is reused on another
                components: [internal-sso]
                severity: high
                countermeasures: [validate-token-claims]
            """
        ),
        encoding="utf-8",
    )

    menu = await call(task_description="SSO login", project_root=str(tmp_path))
    assert "internal-sso" in [c["id"] for c in menu["components"]]

    data = await call(
        task_description="SSO login",
        components="internal-sso",
        project_root=str(tmp_path),
    )
    assert [t["id"] for t in data["assessment"]["threats"]] == ["sso-token-reuse"]


@pytest.mark.anyio
async def test_invalid_project_library_returns_a_clear_error(tmp_path: Path) -> None:
    folder = tmp_path / ".ai-security-crew" / "library"
    folder.mkdir(parents=True)
    (folder / "team.yaml").write_text("threats: [oops\n", encoding="utf-8")

    data = await call(task_description="x", project_root=str(tmp_path))

    assert data["success"] is False
    assert data["error"]["code"] == "invalid_library"
    assert data["details"]


# ---- ATT&CK ----


@pytest.mark.anyio
@pytest.mark.usefixtures("cached_attack")
async def test_review_threats_carry_attack_names() -> None:
    data = await call(task_description="Search page", components="database")

    assessment = data["assessment"]
    sqli = next(t for t in assessment["threats"] if t["id"] == "sql-injection")
    assert sqli["attack"][0] == {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactics": ["initial-access"],
        "revoked": False,
        "revoked_by": None,
    }
    assert assessment["sources"] == {"attack": "ok (ATT&CK 20.0)"}


@pytest.mark.anyio
async def test_review_without_index_has_ids_and_pending_source(
    refresh_calls: list[object],
) -> None:
    data = await call(task_description="Search page", components="database")

    assessment = data["assessment"]
    sqli = next(t for t in assessment["threats"] if t["id"] == "sql-injection")
    assert sqli["attack"] == [{"id": "T1190"}]
    assert assessment["sources"] == {"attack": PENDING_STATUS}
    assert len(refresh_calls) == 1


@pytest.mark.anyio
async def test_menu_call_does_not_touch_attack(refresh_calls: list[object]) -> None:
    data = await call(task_description="Search page")

    assert data["status"] == "needs_components"
    assert refresh_calls == []


# ---- general_project_context ----


async def project_context(**args: Any) -> dict[str, Any]:
    async with Client(main_mcp) as client:
        result = await client.call_tool("general_project_context", args)
    items = result if isinstance(result, list) else result.content
    return json.loads(items[0].text)


@pytest.fixture
def stack_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The issue #50 repo as the server's working directory."""
    root = make_stack50(tmp_path / "stack50")
    monkeypatch.chdir(root)
    return root


@pytest.mark.anyio
async def test_project_context_describes_the_cwd(stack_cwd: Path) -> None:
    data = await project_context()

    assert data["success"] is True
    assert data["root"] == "."
    assert data["iac"]["terraform_providers"] == ["aws"]
    assert {"cloud-compute", "container-image", "ci-pipeline", "web-endpoint"} <= set(
        data["suggested_components"]
    )
    assert {f["kind"] for f in data["flags"]} == {
        "unpinned_action",
        "mutable_image",
        "unpinned_module",
    }
    assert data["sensitive_files_present"] == [".env"]
    assert len(data["existing_threat_model"]["headings"]) == 2
    assert "sca_verify_packages" in data["next_steps"]
    assert "library_warning" not in data
    text = json.dumps(data)
    assert "do-not-read" not in text
    assert str(stack_cwd.parent) not in text


@pytest.mark.anyio
async def test_project_context_accepts_relative_and_absolute_subpaths(
    stack_cwd: Path,
) -> None:
    relative = await project_context(path="infra")
    absolute = await project_context(path=str(stack_cwd / "infra"))

    assert relative["root"] == absolute["root"] == "infra"
    assert relative["iac"] == absolute["iac"]
    assert str(stack_cwd) not in json.dumps(absolute)


@pytest.mark.anyio
@pytest.mark.parametrize("path", ["../..", "/etc", "infra/link"])
async def test_project_context_refuses_paths_outside_cwd(
    stack_cwd: Path, path: str
) -> None:
    (stack_cwd / "infra" / "link").symlink_to("/etc")

    data = await project_context(path=path)

    assert data["success"] is False
    assert data["error"]["code"] == "path_outside_project"
    assert "/etc" not in json.dumps(data)


@pytest.mark.anyio
async def test_project_context_reports_missing_path(stack_cwd: Path) -> None:
    data = await project_context(path="does-not-exist")

    assert data["success"] is False
    assert data["error"]["code"] == "path_not_found"


@pytest.mark.anyio
async def test_project_context_survives_an_invalid_project_library(
    stack_cwd: Path,
) -> None:
    folder = stack_cwd / ".ai-security-crew" / "library"
    folder.mkdir(parents=True)
    (folder / "team.yaml").write_text("threats: [oops\n", encoding="utf-8")

    data = await project_context()

    assert data["success"] is True
    assert data["library_warning"]
    assert "cloud-compute" in data["suggested_components"]


@pytest.mark.anyio
async def test_project_context_clips_huge_workflow_lines(stack_cwd: Path) -> None:
    (stack_cwd / ".github" / "workflows" / "big.yml").write_text(
        "jobs:\n  a:\n    steps:\n      - uses: evil/act@" + "A" * 1_000_000 + "\n",
        encoding="utf-8",
    )

    raw = await project_context()

    def strings(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [s for v in value.values() for s in strings(v)]
        if isinstance(value, list):
            return [s for v in value for s in strings(v)]
        return []

    assert raw["truncated"] is True
    assert max(len(s) for s in strings(raw)) <= 200 + len(OMITTED)


@pytest.mark.anyio
async def test_project_context_uses_the_cwd_library_for_subpaths(
    stack_cwd: Path,
) -> None:
    folder = stack_cwd / ".ai-security-crew" / "library"
    folder.mkdir(parents=True)
    (folder / "team.yaml").write_text("disable: [cloud-compute]\n", encoding="utf-8")

    data = await project_context(path="infra")

    assert data["success"] is True
    assert "library_warning" not in data
    assert "cloud-network" in data["suggested_components"]
    assert "cloud-compute" not in data["suggested_components"]


@pytest.mark.anyio
async def test_project_context_survives_an_unreadable_project_library(
    stack_cwd: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (stack_cwd / ".ai-security-crew" / "library").mkdir(parents=True)

    def denied(self: Path) -> Any:
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "iterdir", denied)

    data = await project_context()

    assert data["success"] is True
    assert data["library_warning"]
    assert "cloud-compute" in data["suggested_components"]
    assert str(stack_cwd) not in json.dumps(data)
