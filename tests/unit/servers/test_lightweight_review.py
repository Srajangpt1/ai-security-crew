"""Tests for the two-call lightweight_security_review tool."""

import json
from pathlib import Path
from textwrap import dedent
from typing import Any

import pytest
from fastmcp import Client

from mcp_security_review.servers.main import main_mcp

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
    assert data["metadata"]["also_consider_total"] >= len(assessment["also_consider"])


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
async def test_sensitive_data_raises_the_risk_level() -> None:
    plain = await call(task_description="Upload", components="file-upload")
    sensitive = await call(
        task_description="Upload", components="file-upload", data_handled="personal_data"
    )

    assert plain["assessment"]["risk_level"] == "high"
    assert sensitive["assessment"]["risk_level"] == "critical"
    assert sensitive["assessment"]["sensitive_data"] == ["personal_data"]


@pytest.mark.anyio
async def test_unknown_component_lists_valid_ids() -> None:
    data = await call(task_description="x", components="file-upload,teleporter")

    assert data["success"] is False
    assert "teleporter" in data["error"]
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
    assert len(json.dumps(data, separators=(',', ':'))) < 16000


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
    assert "invalid" in data["error"]
    assert data["details"]
