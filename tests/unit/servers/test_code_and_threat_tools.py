"""Tests for verify_code_security and perform_threat_model with the library."""

import json
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from mcp_security_review.servers.main import main_mcp


async def call(tool: str, **args: Any) -> dict[str, Any]:
    async with Client(main_mcp) as client:
        result = await client.call_tool(tool, args)
    items = result if isinstance(result, list) else result.content
    return json.loads(items[0].text)


VERIFY = "general_verify_code_security"
THREAT = "threatmodel_perform_threat_model"


@pytest.mark.anyio
async def test_verify_code_uses_components_and_language() -> None:
    data = await call(
        VERIFY,
        file_path="views.py",
        components="file-upload",
    )

    assert data["success"] is True
    assert "technologies_detected" not in data["context"]
    assert data["context"]["components"] == ["file-upload"]
    assert data["context"]["risk_level"] == "high"
    assert "hint" not in data
    assert any("filename" in item for item in data["security_checklist"])
    assert "File:" in data["review_prompt"]


@pytest.mark.anyio
async def test_verify_code_never_sends_the_code_back() -> None:
    code = "def save(f):\n    f.save(f.filename)  # UNIQUE_MARKER_123\n"
    data = await call(VERIFY, code=code, file_path="views.py", components="file-upload")

    assert data["success"] is True
    assert "UNIQUE_MARKER_123" not in json.dumps(data)
    assert "code_to_review" not in data


@pytest.mark.anyio
async def test_verify_code_response_size_does_not_depend_on_the_code() -> None:
    small = await call(VERIFY, components="file-upload")
    large = await call(VERIFY, code="x = 1\n" * 5000, components="file-upload")

    assert len(json.dumps(large)) == len(json.dumps(small))


@pytest.mark.anyio
async def test_verify_code_without_components_gives_a_generic_checklist_and_hint() -> (
    None
):
    data = await call(VERIFY, file_path="a.py")

    assert data["success"] is True
    assert data["context"]["risk_level"] is None
    assert "components" in data["hint"]
    assert data["security_checklist"]


@pytest.mark.anyio
async def test_verify_code_rejects_unknown_components() -> None:
    data = await call(VERIFY, components="teleporter")

    assert data["success"] is False
    assert "file-upload" in data["valid_components"]


@pytest.mark.anyio
async def test_verify_code_reports_an_invalid_project_library(tmp_path: Path) -> None:
    folder = tmp_path / ".ai-security-crew" / "library"
    folder.mkdir(parents=True)
    (folder / "bad.yaml").write_text("threats: [oops\n", encoding="utf-8")

    data = await call(VERIFY, project_root=str(tmp_path))

    assert data["success"] is False
    assert data["details"]


@pytest.mark.anyio
async def test_threat_model_seeds_known_threats_from_the_library() -> None:
    data = await call(
        THREAT,
        title="Avatar upload",
        description="Users upload a profile picture stored in S3",
        components="file-upload,object-storage",
    )

    assert data["success"] is True
    known = data["known_threats"]
    assert known["status"] == "from_library"
    assert known["risk_level"] == "high"
    assert "upload-executable-file" in {t["id"] for t in known["threats"]}
    assert known["countermeasures"]
    assert "security_signals" not in data


@pytest.mark.anyio
async def test_threat_model_without_components_returns_the_menu() -> None:
    data = await call(THREAT, title="Avatar upload", description="Users upload files")

    known = data["known_threats"]
    assert known["status"] == "needs_components"
    assert "file-upload" in [c["id"] for c in known["components"]]
    # The template is still returned so the agent can proceed.
    assert data["template"]


@pytest.mark.anyio
async def test_threat_model_rejects_unknown_components() -> None:
    data = await call(THREAT, title="x", description="y", components="teleporter")

    assert data["success"] is False
    assert "valid_components" in data


@pytest.mark.anyio
async def test_threat_model_keeps_previous_models_as_reference() -> None:
    previous = json.dumps([{"title": "Auth v1", "source": "wiki", "content": "..."}])
    data = await call(
        THREAT,
        title="Login",
        description="JWT login",
        components="authentication",
        previous_models_json=previous,
    )

    assert [m["title"] for m in data["previous_threat_models"]] == ["Auth v1"]
