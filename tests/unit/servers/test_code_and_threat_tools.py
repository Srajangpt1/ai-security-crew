"""Tests for verify_code_security and perform_threat_model with the library."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from mcp_security_review.library import builtin_library, describe
from mcp_security_review.providers.attack import PENDING_STATUS, AttackIndex
from mcp_security_review.servers import library_support
from mcp_security_review.servers.main import main_mcp


async def call(tool: str, **args: Any) -> dict[str, Any]:
    async with Client(main_mcp) as client:
        result = await client.call_tool(tool, args)
    items = result if isinstance(result, list) else result.content
    return json.loads(items[0].text)


VERIFY = "general_verify_code_security"
THREAT = "threatmodel_perform_threat_model"
ATTACK = "threatmodel_attack_technique"


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


# ---- ATT&CK in reviews ----


@pytest.mark.anyio
@pytest.mark.usefixtures("cached_attack")
async def test_verify_focus_areas_name_attack_techniques() -> None:
    data = await call(VERIFY, components="database")

    assert (
        "Attacker input changes the meaning of a database query "
        "(ATT&CK T1190 Exploit Public-Facing Application)"
    ) in data["focus_areas"]
    assert "(ATT&CK T1190 Exploit Public-Facing Application)" in data["review_prompt"]


@pytest.mark.anyio
@pytest.mark.usefixtures("cached_attack")
async def test_verify_focus_areas_skip_revoked_techniques(tmp_path: Path) -> None:
    folder = tmp_path / ".ai-security-crew" / "library"
    folder.mkdir(parents=True)
    (folder / "team.yaml").write_text(
        "threats:\n"
        "  - id: keys-in-repo\n"
        "    name: Deploy keys sit in the repo\n"
        "    components: [secrets-and-config]\n"
        "    severity: high\n"
        "    attack: [T1081, T1064, T1552.001]\n"  # revoked, deprecated, current
        "    countermeasures: [secrets-manager]\n",
        encoding="utf-8",
    )

    data = await call(
        VERIFY, components="secrets-and-config", project_root=str(tmp_path)
    )

    assert (
        "Deploy keys sit in the repo (ATT&CK T1552.001 Credentials In Files)"
        in data["focus_areas"]
    )


@pytest.mark.anyio
async def test_verify_focus_areas_are_plain_without_an_index(
    refresh_calls: list[object],
) -> None:
    data = await call(VERIFY, components="database")

    assert (
        "Attacker input changes the meaning of a database query" in data["focus_areas"]
    )
    assert not any("ATT&CK" in area for area in data["focus_areas"])
    assert len(refresh_calls) == 1


@pytest.mark.anyio
@pytest.mark.usefixtures("cached_attack")
async def test_threat_model_known_threats_carry_attack_names() -> None:
    data = await call(
        THREAT, title="Avatar upload", description="Upload", components="file-upload"
    )

    known = data["known_threats"]
    upload = next(t for t in known["threats"] if t["id"] == "upload-executable-file")
    names = {a["id"]: a.get("name") for a in upload["attack"]}
    assert names["T1505.003"] == "Web Shell"
    assert known["sources"] == {"attack": "ok (ATT&CK 20.0)"}


@pytest.mark.anyio
async def test_threat_model_without_index_is_pending(
    refresh_calls: list[object],
) -> None:
    data = await call(
        THREAT, title="Avatar upload", description="Upload", components="file-upload"
    )

    known = data["known_threats"]
    upload = next(t for t in known["threats"] if t["id"] == "upload-executable-file")
    assert {"id": "T1505.003"} in upload["attack"]
    assert known["sources"] == {"attack": PENDING_STATUS}
    assert len(refresh_calls) == 1


# ---- threatmodel_attack_technique ----


@pytest.mark.anyio
@pytest.mark.usefixtures("cached_attack")
async def test_attack_tool_by_id() -> None:
    data = await call(ATTACK, technique_id="t1190")

    assert data["success"] is True
    assert data["attack_version"] == "20.0"
    tech = data["technique"]
    assert tech["id"] == "T1190"
    assert tech["name"] == "Exploit Public-Facing Application"
    assert tech["url"] == "https://attack.mitre.org/techniques/T1190"
    assert tech["mitigations"]
    assert "warning" not in data


@pytest.mark.anyio
@pytest.mark.usefixtures("cached_attack")
async def test_attack_tool_by_query() -> None:
    data = await call(ATTACK, query="credential stuffing")

    assert data["success"] is True
    assert data["attack_version"] == "20.0"
    assert data["matches"][0]["id"] == "T1110.004"
    assert data["matches"][0]["name"] == "Credential Stuffing"
    assert len(data["matches"]) <= 10


@pytest.mark.anyio
@pytest.mark.usefixtures("cached_attack")
async def test_attack_tool_revoked_warning() -> None:
    data = await call(ATTACK, technique_id="T1081")

    assert data["success"] is True
    assert data["technique"]["revoked"] is True
    assert data["warning"] == "Revoked in ATT&CK; use T1552.001"


@pytest.mark.anyio
@pytest.mark.usefixtures("cached_attack")
async def test_attack_tool_unknown_id() -> None:
    data = await call(ATTACK, technique_id="T9999")

    assert data["success"] is False
    assert data["error"]["code"] == "technique_not_found"


@pytest.mark.anyio
@pytest.mark.parametrize("bad", ["T19", "TA0001", "T1190.4", "1190", "T1190; rm"])
async def test_attack_tool_invalid_id(bad: str, refresh_calls: list[object]) -> None:
    data = await call(ATTACK, technique_id=bad)

    assert data["success"] is False
    assert data["error"]["code"] == "invalid_technique_id"
    assert refresh_calls == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "args",
    [
        {"technique_id": "T1190", "query": "phishing"},
        {},
        {"technique_id": "  ", "query": ""},
        {"query": "x"},
        {"query": "x" * 101},
    ],
)
async def test_attack_tool_rejects_bad_arguments(args: dict[str, str]) -> None:
    data = await call(ATTACK, **args)

    assert data["success"] is False
    assert data["error"]["code"] == "invalid_arguments"
    assert data["error"]["hint"]


@pytest.mark.anyio
async def test_attack_tool_pending_starts_a_refresh(
    refresh_calls: list[object],
) -> None:
    data = await call(ATTACK, technique_id="T1190")

    assert data["success"] is False
    assert data["error"]["code"] == "attack_data_pending"
    assert data["error"]["hint"] == "Retry in a minute; the catalogue is downloading."
    assert len(refresh_calls) == 1


@pytest.mark.anyio
async def test_attack_tool_answers_from_a_stale_index_and_refreshes(
    attack_data: dict[str, Any],
    refresh_calls: list[object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale = AttackIndex.from_dict(attack_data)
    stale.fetched_at = datetime.now(UTC) - timedelta(days=30)
    monkeypatch.setattr(
        library_support.AttackIndex, "load", classmethod(lambda cls, cache=None: stale)
    )

    data = await call(ATTACK, technique_id="T1190")

    assert data["success"] is True
    assert len(refresh_calls) == 1


@pytest.mark.anyio
async def test_attack_tool_is_read_only() -> None:
    tools = await main_mcp.get_tools()
    assert "write" not in tools[ATTACK].tags


UPDATE = "threatmodel_update_threat_model_file"


def _model(*statuses: str) -> str:
    return json.dumps(
        {
            "title": "Upload service",
            "threats": [
                {"id": f"TM-{i}", "what_can_go_wrong": "x", "status": status}
                for i, status in enumerate(statuses, start=1)
            ],
        }
    )


@pytest.mark.anyio
async def test_update_reports_created_then_overwritten_then_appended(
    tmp_path: Path,
) -> None:
    target = str(tmp_path / "threat-model.md")

    created = await call(UPDATE, threat_model_json=_model("open"), file_path=target)
    overwritten = await call(UPDATE, threat_model_json=_model("open"), file_path=target)
    appended = await call(
        UPDATE, threat_model_json=_model("open"), file_path=target, append=True
    )

    assert created["action"] == "created"
    assert overwritten["action"] == "overwritten"
    assert appended["action"] == "appended"


@pytest.mark.anyio
async def test_append_to_a_missing_file_reports_created(tmp_path: Path) -> None:
    target = str(tmp_path / "threat-model.md")

    data = await call(
        UPDATE, threat_model_json=_model("open"), file_path=target, append=True
    )

    assert data["action"] == "created"


@pytest.mark.anyio
async def test_status_counts_sum(tmp_path: Path) -> None:
    data = await call(
        UPDATE,
        threat_model_json=_model("open", "in_progress", "mitigated", "accepted"),
        file_path=str(tmp_path / "threat-model.md"),
    )

    stats = data["stats"]
    assert stats["threats_documented"] == 4
    assert (stats["open"], stats["in_progress"]) == (1, 1)
    assert (stats["mitigated"], stats["accepted"]) == (1, 1)
    statuses = ("open", "in_progress", "mitigated", "accepted")
    assert sum(stats[s] for s in statuses) == stats["threats_documented"]


@pytest.mark.anyio
async def test_unknown_status_counts_as_open(tmp_path: Path) -> None:
    data = await call(
        UPDATE,
        threat_model_json=_model("wontfix", "mitigated"),
        file_path=str(tmp_path / "threat-model.md"),
    )

    assert data["stats"]["open"] == 1
    assert data["stats"]["mitigated"] == 1


@pytest.mark.anyio
async def test_update_tool_is_a_write_tool() -> None:
    tools = await main_mcp.get_tools()
    assert "write" in tools[UPDATE].tags


def test_also_consider_total_matches_or_flags_truncation() -> None:
    library = builtin_library()
    upload = library.resolve(["file-upload"])
    database = library.resolve(["database"])

    long_view = describe(upload, 8)
    short_view = describe(database, 8)

    assert len(upload.also_consider) > 8
    assert len(long_view["also_consider"]) == 8
    assert long_view["also_consider_total"] == len(upload.also_consider)
    assert long_view["also_consider_truncated"] is True
    assert short_view["also_consider_total"] == len(short_view["also_consider"])
    assert short_view["also_consider_truncated"] is False


@pytest.mark.anyio
async def test_review_reports_also_consider_total_once() -> None:
    async with Client(main_mcp) as client:
        result = await client.call_tool(
            "general_lightweight_security_review",
            {"task_description": "Upload", "components": "file-upload"},
        )
    items = result if isinstance(result, list) else result.content
    data = json.loads(items[0].text)

    assert data["assessment"]["also_consider_truncated"] is True
    assert data["assessment"]["also_consider_total"] > 8
    assert "also_consider_total" not in data["metadata"]
