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
    assert len(library.components) >= 20
    assert len(library.threats) >= 60
    assert len(library.countermeasures) >= 60


def test_every_component_has_threats(library: Library) -> None:
    used = {c for t in library.threats.values() for c in t.components}
    assert set(library.components) - used == set()


def test_every_countermeasure_is_used(library: Library) -> None:
    used = {m for t in library.threats.values() for m in t.countermeasures}
    assert set(library.countermeasures) - used == set()


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
