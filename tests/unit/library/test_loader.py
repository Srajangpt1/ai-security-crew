"""Tests for loading and merging project library files."""

from pathlib import Path
from textwrap import dedent

import pytest

from mcp_security_review.library import LibraryError, load_library


def write_library(root: Path, name: str, text: str) -> None:
    folder = root / ".ai-security-crew" / "library"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(dedent(text), encoding="utf-8")


def test_no_project_files_returns_builtin(tmp_path: Path) -> None:
    library = load_library(tmp_path)
    assert "file-upload" in library.components


def test_project_can_add_component_threat_and_countermeasure(tmp_path: Path) -> None:
    write_library(
        tmp_path,
        "team.yaml",
        """
        components:
          - id: internal-sso
            name: Company SSO
            applies_when: The feature signs users in through our SSO.
        threats:
          - id: sso-token-reuse
            name: A token meant for one app is reused on another
            components: [internal-sso]
            severity: high
            cwe: [CWE-345]
            countermeasures: [check-sso-audience, validate-token-claims]
        countermeasures:
          - id: check-sso-audience
            name: Check the SSO audience
            how_to: Reject tokens whose audience is not this app.
            effort: low
        """,
    )

    library = load_library(tmp_path)
    result = library.resolve(["internal-sso"])

    assert [t.id for t in result.threats] == ["sso-token-reuse"]
    assert {m.id for m in result.countermeasures} == {
        "check-sso-audience",
        "validate-token-claims",
    }


def test_duplicate_builtin_id_needs_override(tmp_path: Path) -> None:
    write_library(
        tmp_path,
        "team.yaml",
        """
        components:
          - id: database
            name: Our database
            applies_when: Always.
        """,
    )
    with pytest.raises(LibraryError) as info:
        load_library(tmp_path)
    assert "already exists" in str(info.value)
    assert "override: true" in str(info.value)


def test_override_replaces_builtin_entry(tmp_path: Path) -> None:
    write_library(
        tmp_path,
        "team.yaml",
        """
        components:
          - id: database
            name: Our database
            applies_when: Always.
            override: true
        """,
    )
    assert load_library(tmp_path).components["database"].name == "Our database"


def test_duplicate_ids_across_project_files_are_rejected(tmp_path: Path) -> None:
    entry = """
        components:
          - id: my-thing
            name: Thing
            applies_when: Sometimes.
        """
    write_library(tmp_path, "a.yaml", entry)
    write_library(tmp_path, "b.yaml", entry)
    with pytest.raises(LibraryError, match="duplicate component id 'my-thing'"):
        load_library(tmp_path)


def test_disable_removes_entries_and_prunes_references(tmp_path: Path) -> None:
    write_library(
        tmp_path,
        "team.yaml",
        """
        disable: [upload-allow-list, webhook-replay, third-party-script-compromise]
        """,
    )
    library = load_library(tmp_path)

    assert "upload-allow-list" not in library.countermeasures
    assert "webhook-replay" not in library.threats
    # Still present because it has other countermeasures left.
    assert "upload-executable-file" in library.threats
    assert "upload-allow-list" not in library.threats["upload-executable-file"].countermeasures


def test_disabling_every_countermeasure_of_a_threat_drops_it(tmp_path: Path) -> None:
    write_library(tmp_path, "team.yaml", "disable: [parameterized-queries]\n")
    library = load_library(tmp_path)
    assert "sql-injection" not in library.threats


def test_disabling_a_component_drops_threats_that_only_used_it(tmp_path: Path) -> None:
    write_library(tmp_path, "team.yaml", "disable: [email-sending]\n")
    library = load_library(tmp_path)

    assert "email-sending" not in library.components
    assert "email-header-injection" not in library.threats
    # Shared with another component, so it stays.
    assert library.threats["insecure-password-reset"].components == ["authentication"]


def test_unknown_reference_is_reported(tmp_path: Path) -> None:
    write_library(
        tmp_path,
        "team.yaml",
        """
        threats:
          - id: lonely-threat
            name: Points at nothing
            components: [no-such-component]
            severity: low
            countermeasures: [no-such-fix]
        """,
    )
    with pytest.raises(LibraryError) as info:
        load_library(tmp_path)
    message = str(info.value)
    assert "unknown component 'no-such-component'" in message
    assert "unknown countermeasure 'no-such-fix'" in message


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("components:\n  - id: Bad_Slug\n    name: x\n    applies_when: y\n", "id"),
        (
            "threats:\n  - id: t\n    name: x\n    components: [database]\n"
            "    severity: scary\n    countermeasures: [parameterized-queries]\n",
            "severity",
        ),
        (
            "threats:\n  - id: t\n    name: x\n    components: [database]\n"
            "    severity: low\n    cwe: [89]\n    countermeasures: [parameterized-queries]\n",
            "cwe",
        ),
        (
            "countermeasures:\n  - id: c\n    name: x\n    how_to: y\n"
            "    effort: low\n    asvs: [V1.2.4]\n",
            "asvs",
        ),
        (
            "components:\n  - id: c\n    name: x\n    applies_when: y\n    colour: red\n",
            "colour",
        ),
        ("surprise: true\n", "unknown top-level key 'surprise'"),
    ],
)
def test_invalid_entries_are_rejected_with_clear_messages(
    tmp_path: Path, body: str, expected: str
) -> None:
    write_library(tmp_path, "team.yaml", body)
    with pytest.raises(LibraryError) as info:
        load_library(tmp_path)
    assert expected in str(info.value)


def test_invalid_yaml_is_reported(tmp_path: Path) -> None:
    write_library(tmp_path, "team.yaml", "components: [unclosed\n")
    with pytest.raises(LibraryError, match="invalid YAML"):
        load_library(tmp_path)


def test_all_problems_are_reported_together(tmp_path: Path) -> None:
    write_library(
        tmp_path,
        "team.yaml",
        """
        components:
          - id: Bad_One
            name: x
            applies_when: y
          - id: Bad_Two
            name: x
            applies_when: y
        """,
    )
    with pytest.raises(LibraryError) as info:
        load_library(tmp_path)
    assert len(info.value.errors) >= 2
