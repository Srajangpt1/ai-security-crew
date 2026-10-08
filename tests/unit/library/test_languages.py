"""Tests for language hints in the threat library."""

from pathlib import Path
from textwrap import dedent

import pytest

from mcp_security_review.library import LibraryError, load_library


@pytest.fixture(scope="module")
def library():
    return load_library(Path("/nonexistent-project-root"))


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("app/auth.py", "python"),
        ("web/page.js", "javascript"),
        ("web/page.ts", "typescript"),
        ("web/Page.tsx", "react"),
        ("web/Page.jsx", "react"),
        ("Main.java", "java"),
        ("schema.sql", "sql"),
        ("main.go", "go"),
        ("SRC/APP.PY", "python"),
    ],
)
def test_language_is_chosen_by_file_extension(library, path, expected) -> None:
    assert library.language_for(file_path=path).id == expected


def test_explicit_language_wins_over_extension(library) -> None:
    assert library.language_for("x.py", "Go").id == "go"


def test_unknown_extension_or_language_gives_none(library) -> None:
    assert library.language_for("README.md") is None
    assert library.language_for(language="cobol") is None
    assert library.language_for() is None


def test_baseline_countermeasures_are_flagged(library) -> None:
    ids = {m.id for m in library.baseline_countermeasures()}
    assert ids == {
        "secrets-manager",
        "parameterized-queries",
        "server-side-validation",
        "log-without-secrets",
        "generic-error-messages",
    }


def test_project_can_add_a_language(tmp_path: Path) -> None:
    folder = tmp_path / ".ai-security-crew" / "library"
    folder.mkdir(parents=True)
    (folder / "team.yaml").write_text(
        dedent(
            """
            languages:
              - id: kotlin
                name: Kotlin
                extensions: [.kt]
                focus: [Unsafe WebView JavaScript bridges]
            """
        ),
        encoding="utf-8",
    )
    assert load_library(tmp_path).language_for("A.kt").id == "kotlin"


def test_bad_extension_format_is_rejected(tmp_path: Path) -> None:
    folder = tmp_path / ".ai-security-crew" / "library"
    folder.mkdir(parents=True)
    (folder / "team.yaml").write_text(
        "languages:\n  - id: kotlin\n    name: Kotlin\n    extensions: [kt]\n",
        encoding="utf-8",
    )
    with pytest.raises(LibraryError, match="extensions"):
        load_library(tmp_path)


def test_disable_removes_a_language(tmp_path: Path) -> None:
    folder = tmp_path / ".ai-security-crew" / "library"
    folder.mkdir(parents=True)
    (folder / "team.yaml").write_text("disable: [go]\n", encoding="utf-8")
    assert load_library(tmp_path).language_for("main.go") is None
