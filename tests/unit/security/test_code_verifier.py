"""Tests for the library-driven code review context."""

import pytest

from mcp_security_review.library import UnknownComponentError
from mcp_security_review.security import CodeReviewContextBuilder

def build(**kwargs):
    return CodeReviewContextBuilder().build_review_context(**kwargs)


def test_no_components_gives_only_the_baseline_checklist() -> None:
    context = build(file_path="app/views.py")

    assert context.components == []
    assert context.review_focus_areas == []
    assert len(context.security_checklist) == 5


def test_components_target_the_checklist_at_their_threats() -> None:
    context = build(file_path="views.py", components=["file-upload"])

    assert context.components == ["file-upload"]
    assert context.risk_level == "high"
    assert any("../" in area for area in context.review_focus_areas)
    assert any(
        item.startswith("Never use the user's filename or path")
        for item in context.security_checklist
    )


def test_baseline_checks_are_always_included() -> None:
    context = build()

    joined = " ".join(context.security_checklist)
    assert "parameterized queries" in joined.lower()
    assert "secrets" in joined.lower()


def test_checklist_has_no_duplicates() -> None:
    context = build(file_path="views.py", components=["database", "file-upload"])
    assert len(context.security_checklist) == len(set(context.security_checklist))


def test_no_components_means_no_risk_level() -> None:
    context = build(file_path="views.py")
    assert context.risk_level is None
    assert "Risk Level" not in context.review_prompt


def test_sensitive_data_raises_the_risk_level() -> None:
    context = build(components=["file-upload"], data_handled=["personal_data"])
    assert context.risk_level == "critical"


def test_unknown_component_is_rejected() -> None:
    with pytest.raises(UnknownComponentError):
        build(components=["teleporter"])


def test_review_prompt_contains_the_checklist_but_no_code() -> None:
    context = build(file_path="views.py", components=["file-upload"])

    assert "```" not in context.review_prompt
    assert "already in your context" in context.review_prompt
    assert "### Security Checklist" in context.review_prompt
    assert "**Components:** file-upload" in context.review_prompt
    assert "Language" not in context.review_prompt
