"""Load the built-in threat library and merge a project's own library files."""

import logging
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from .library import Library
from .models import Component, Countermeasure, Threat

logger = logging.getLogger("mcp-security-review.library")

USER_LIBRARY_DIR = Path(".ai-security-crew") / "library"

_KINDS: dict[str, type[BaseModel]] = {
    "components": Component,
    "threats": Threat,
    "countermeasures": Countermeasure,
}


class LibraryError(ValueError):
    """Raised when library files are invalid. Holds every problem found."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("Invalid threat library:\n- " + "\n- ".join(errors))
        self.errors = errors


def load_library(project_root: Path | None = None) -> Library:
    """Load the built-in library plus any project files.

    Project files live in ``<project_root>/.ai-security-crew/library/`` and use
    the same three keys (``components``, ``threats``, ``countermeasures``).
    A project entry may reuse a built-in id only with ``override: true``, and a
    ``disable`` list removes built-in entries by id.

    Args:
        project_root: Folder to look in. Defaults to the current directory.

    Returns:
        The merged, validated library.

    Raises:
        LibraryError: If any file is malformed or any reference is broken.
    """
    builtin = _builtin_library()
    root = project_root if project_root is not None else Path.cwd()
    user_dir = root / USER_LIBRARY_DIR
    files = (
        sorted([*user_dir.glob("*.yaml"), *user_dir.glob("*.yml")])
        if user_dir.is_dir()
        else []
    )
    if not files:
        return builtin

    errors: list[str] = []
    components = dict(builtin.components)
    threats = dict(builtin.threats)
    countermeasures = dict(builtin.countermeasures)
    added: dict[str, set[str]] = {kind: set() for kind in _KINDS}
    disabled: set[str] = set()

    for path in files:
        data = _read_yaml(path, errors)
        disabled.update(_as_str_list(data.get("disable"), path, errors))
        for kind, target in (
            ("components", components),
            ("threats", threats),
            ("countermeasures", countermeasures),
        ):
            for entry in _parse_entries(kind, data.get(kind), path, errors):
                if entry.id in added[kind]:
                    errors.append(f"{path.name}: duplicate {kind[:-1]} id '{entry.id}'")
                elif entry.id in target and not entry.override:
                    errors.append(
                        f"{path.name}: {kind[:-1]} '{entry.id}' already exists; "
                        "set 'override: true' to replace it"
                    )
                else:
                    target[entry.id] = entry  # type: ignore[assignment]
                    added[kind].add(entry.id)

    if errors:
        raise LibraryError(errors)

    components, threats, countermeasures = _apply_disable(
        disabled, components, threats, countermeasures
    )
    library = Library(components, threats, countermeasures)
    check_references(library)
    return library


def check_references(library: Library) -> None:
    """Raise LibraryError if any reference in the library is broken."""
    errors: list[str] = []
    for c in library.components.values():
        for implied in c.implies:
            if implied not in library.components:
                errors.append(
                    f"component '{c.id}' implies unknown component '{implied}'"
                )
    for t in library.threats.values():
        if not t.components:
            errors.append(f"threat '{t.id}' lists no components")
        if not t.countermeasures:
            errors.append(f"threat '{t.id}' lists no countermeasures")
        for comp in t.components:
            if comp not in library.components:
                errors.append(f"threat '{t.id}' uses unknown component '{comp}'")
        for cm in t.countermeasures:
            if cm not in library.countermeasures:
                errors.append(f"threat '{t.id}' uses unknown countermeasure '{cm}'")
    if errors:
        raise LibraryError(errors)


@lru_cache(maxsize=1)
def _builtin_library() -> Library:
    errors: list[str] = []
    base = resources.files("mcp_security_review.library")
    loaded: dict[str, dict[str, Any]] = {}
    for kind, model in _KINDS.items():
        text = base.joinpath(f"{kind}.yaml").read_text(encoding="utf-8")
        entries = _parse_entries(
            kind,
            _safe_load(text, f"{kind}.yaml", errors).get(kind),
            Path(f"{kind}.yaml"),
            errors,
        )
        ids: dict[str, Any] = {}
        for entry in entries:
            if entry.id in ids:
                errors.append(f"{kind}.yaml: duplicate id '{entry.id}'")
            ids[entry.id] = entry
        loaded[kind] = ids
        del model
    if errors:
        raise LibraryError(errors)
    library = Library(
        loaded["components"],
        loaded["threats"],
        loaded["countermeasures"],
    )
    check_references(library)
    return library


def _read_yaml(path: Path, errors: list[str]) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"{path.name}: cannot read file ({exc})")
        return {}
    return _safe_load(text, path.name, errors)


def _safe_load(text: str, name: str, errors: list[str]) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        errors.append(f"{name}: invalid YAML ({exc})")
        return {}
    if data is None:
        return {}
    if not isinstance(data, dict):
        errors.append(f"{name}: top level must be a mapping")
        return {}
    unknown = set(data) - set(_KINDS) - {"disable"}
    for key in sorted(unknown):
        errors.append(f"{name}: unknown top-level key '{key}'")
    return data


def _as_str_list(value: Any, path: Path, errors: list[str]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        errors.append(f"{path.name}: 'disable' must be a list of ids")
        return []
    return list(value)


def _parse_entries(kind: str, raw: Any, path: Path, errors: list[str]) -> list[Any]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        errors.append(f"{path.name}: '{kind}' must be a list")
        return []
    model = _KINDS[kind]
    parsed: list[Any] = []
    for index, item in enumerate(raw):
        try:
            parsed.append(model.model_validate(item))
        except ValidationError as exc:
            label = (
                item.get("id", f"#{index + 1}")
                if isinstance(item, dict)
                else f"#{index + 1}"
            )
            for problem in exc.errors():
                where = ".".join(str(p) for p in problem["loc"])
                errors.append(
                    f"{path.name}: {kind[:-1]} '{label}': {where}: {problem['msg']}"
                )
    return parsed


def _apply_disable(
    disabled: set[str],
    components: dict[str, Component],
    threats: dict[str, Threat],
    countermeasures: dict[str, Countermeasure],
) -> tuple[dict[str, Component], dict[str, Threat], dict[str, Countermeasure]]:
    """Remove disabled ids and prune anything left dangling or empty."""
    if not disabled:
        return components, threats, countermeasures

    components = {k: v for k, v in components.items() if k not in disabled}
    countermeasures = {k: v for k, v in countermeasures.items() if k not in disabled}
    components = {
        k: v.model_copy(update={"implies": [i for i in v.implies if i in components]})
        for k, v in components.items()
    }
    kept: dict[str, Threat] = {}
    for key, threat in threats.items():
        if key in disabled:
            continue
        remaining_components = [c for c in threat.components if c in components]
        remaining_cms = [m for m in threat.countermeasures if m in countermeasures]
        if remaining_components and remaining_cms:
            kept[key] = threat.model_copy(
                update={
                    "components": remaining_components,
                    "countermeasures": remaining_cms,
                }
            )
        else:
            logger.info(
                "Dropping threat '%s' because its components or countermeasures were disabled",
                key,
            )
    return components, kept, countermeasures
