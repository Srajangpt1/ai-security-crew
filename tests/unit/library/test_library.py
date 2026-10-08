"""Tests for the built-in threat library and the component lookup."""

from pathlib import Path

import pytest

from mcp_security_review.library import (
    Severity,
    UnknownComponentError,
    load_library,
)
from mcp_security_review.library.library import Library

ASVS_IDS = {
    line.strip()
    for line in (Path(__file__).parent / "asvs_5_0_0_ids.txt")
    .read_text(encoding="utf-8")
    .splitlines()
    if line.strip() and not line.startswith("#")
}


@pytest.fixture(scope="module")
def library() -> Library:
    return load_library(Path("/nonexistent-project-root"))


def test_builtin_library_is_not_empty(library: Library) -> None:
    assert len(library.components) >= 25
    assert len(library.threats) >= 85
    assert len(library.countermeasures) >= 85


def test_every_component_has_threats(library: Library) -> None:
    used = {c for t in library.threats.values() for c in t.components}
    assert set(library.components) - used == set()


def test_every_countermeasure_is_used(library: Library) -> None:
    used = {m for t in library.threats.values() for m in t.countermeasures}
    assert set(library.countermeasures) - used == set()


MCP_TOP10 = dict(
    line.split("\t", 1)
    for line in (Path(__file__).parent / "mcp_top10_2025.txt")
    .read_text(encoding="utf-8")
    .splitlines()
    if line.strip() and not line.startswith("#")
)


def test_cited_mcp_top10_ids_exist(library: Library) -> None:
    cited = {i for t in library.threats.values() for i in t.mcp_top10}
    assert len(MCP_TOP10) == 10
    assert cited
    assert cited - set(MCP_TOP10) == set()


def test_agent_threats_are_mapped_to_the_mcp_top10(library: Library) -> None:
    assert library.threats["prompt-injection"].mcp_top10 == ["MCP06:2025"]
    assert library.threats["excessive-agent-permissions"].mcp_top10 == ["MCP02:2025"]
    assert "MCP03:2025" in library.threats["untrusted-mcp-server"].mcp_top10
    assert "MCP01:2025" in library.threats["agent-reads-secrets"].mcp_top10
    # Ordinary web threats are not forced into the MCP list.
    assert library.threats["sql-injection"].mcp_top10 == []


def test_cryptography_and_transport_threats_exist(library: Library) -> None:
    crypto = library.resolve(["cryptography"])
    transport = library.resolve(["transport-security"])

    assert {"weak-crypto-algorithms", "hardcoded-crypto-keys"} <= {
        t.id for t in crypto.threats
    }
    assert "CWE-327" in {c for t in crypto.threats for c in t.cwe}
    assert {"cleartext-transport", "outdated-tls"} <= {t.id for t in transport.threats}


def test_cited_asvs_ids_exist(library: Library) -> None:
    cited = {a for m in library.countermeasures.values() for a in m.asvs}
    assert cited
    assert cited - ASVS_IDS == set()


def test_expand_adds_implied_components(library: Library) -> None:
    assert library.expand(["file-upload"]) == ["file-upload", "web-endpoint"]


def test_expand_keeps_order_and_drops_duplicates(library: Library) -> None:
    result = library.expand(["web-endpoint", "file-upload", "web-endpoint"])
    assert result == ["web-endpoint", "file-upload"]


def test_unknown_component_is_rejected_with_valid_ids(library: Library) -> None:
    with pytest.raises(UnknownComponentError) as info:
        library.resolve(["file-upload", "teleporter"])
    assert info.value.unknown == ["teleporter"]
    assert "file-upload" in info.value.valid


def test_upload_example_returns_upload_threats(library: Library) -> None:
    result = library.resolve(["file-upload", "object-storage"])
    ids = {t.id for t in result.threats}

    assert {"upload-executable-file", "upload-path-traversal", "public-bucket"} <= ids
    assert result.risk_level is Severity.HIGH
    assert result.components == ["file-upload", "object-storage", "web-endpoint"]


def test_implied_only_threats_do_not_drive_the_result(library: Library) -> None:
    result = library.resolve(["file-upload"])

    direct = {t.id for t in result.threats}
    assert "csrf" not in direct
    assert "csrf" in {t.id for t in result.also_consider}
    # A critical generic web threat must not raise the level of an upload review.
    assert result.risk_level is Severity.HIGH


def test_threats_are_sorted_most_severe_first(library: Library) -> None:
    result = library.resolve(["authentication", "database"])
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    ranks = [order.index(t.severity) for t in result.threats]
    assert ranks == sorted(ranks)


def test_countermeasures_are_deduplicated_with_mitigated_threats(
    library: Library,
) -> None:
    result = library.resolve(["file-upload"])

    ids = [m.id for m in result.countermeasures]
    assert len(ids) == len(set(ids))
    assert result.mitigates["upload-rename-and-isolate"] == [
        "upload-executable-file",
        "upload-path-traversal",
    ]


def test_sensitive_data_raises_risk_one_step(library: Library) -> None:
    base = library.resolve(["file-upload"])
    raised = library.resolve(["file-upload"], ["personal_data"])

    assert base.risk_level is Severity.HIGH
    assert raised.risk_level is Severity.CRITICAL
    assert raised.sensitive_data == ["personal_data"]


def test_sensitive_data_kinds_accept_hyphens_and_case(library: Library) -> None:
    result = library.resolve(["file-upload"], ["Personal-Data", "personal_data"])

    assert result.sensitive_data == ["personal_data"]
    assert result.risk_level is Severity.CRITICAL


def test_unknown_sensitive_data_kinds_are_ignored(library: Library) -> None:
    result = library.resolve(["file-upload"], ["favorite_color"])
    assert result.sensitive_data == []
    assert result.risk_level is Severity.HIGH


def test_critical_stays_critical_with_sensitive_data(library: Library) -> None:
    result = library.resolve(["database"], ["credentials"])
    assert result.risk_level is Severity.CRITICAL


def test_menu_lists_every_component(library: Library) -> None:
    menu = library.menu()
    assert [m["id"] for m in menu] == list(library.components)
    assert all(m["applies_when"] for m in menu)


def test_baseline_countermeasures_are_flagged(library: Library) -> None:
    ids = {m.id for m in library.baseline_countermeasures()}
    assert ids == {
        "secrets-manager",
        "parameterized-queries",
        "server-side-validation",
        "log-without-secrets",
        "generic-error-messages",
    }
