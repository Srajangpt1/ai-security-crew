"""Tests for the library-driven code review context."""

import pytest

from mcp_security_review.library import UnknownComponentError
from mcp_security_review.security import CodeReviewContextBuilder

CODE = "def upload(f):\n    f.save('/var/www/' + f.filename)\n"


def build(**kwargs):
    return CodeReviewContextBuilder().build_review_context(code=CODE, **kwargs)


def test_language_comes_from_the_file_extension() -> None:
    context = build(file_path="app/views.py")

    assert context.technologies_detected == ["python"]
    assert "Unsafe deserialization (pickle)" in context.review_focus_areas
    assert "subprocess calls use shell=False" in context.security_checklist


def test_explicit_language_overrides_the_extension() -> None:
    context = build(file_path="notes.txt", language="go")
    assert context.technologies_detected == ["go"]


def test_code_content_is_never_used_to_guess_the_language() -> None:
    # Obvious Python, but without a path or language nothing is guessed.
    context = build()
    assert context.technologies_detected == []


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


def test_review_prompt_contains_the_code_and_checklist() -> None:
    context = build(file_path="views.py", components=["file-upload"])

    assert CODE in context.review_prompt
    assert "### Security Checklist" in context.review_prompt
    assert "**Components:** file-upload" in context.review_prompt
    assert "**Language:** python" in context.review_prompt
