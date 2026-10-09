"""Lockfile parser for resolving actual runtime dependency graphs.

Parses common lockfile formats to get the *resolved* dependency set
(what's actually installed at runtime), not just the declared deps.

Supports:
- requirements.txt / requirements-*.txt  (with PEP 508 markers)
- uv.lock  (TOML-based, uv package manager)
- poetry.lock  (TOML-based, Poetry)
- package-lock.json v2/v3  (npm)
- yarn.lock  (Yarn classic and berry)
- Pipfile.lock  (Pipenv)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class LockfileFormat(str, Enum):
    REQUIREMENTS_TXT = "requirements.txt"
    UV_LOCK = "uv.lock"
    POETRY_LOCK = "poetry.lock"
    PACKAGE_LOCK_JSON = "package-lock.json"
    YARN_LOCK = "yarn.lock"
    PIPFILE_LOCK = "Pipfile.lock"
    UNKNOWN = "unknown"


@dataclass
class LockedDependency:
    """A single dependency as resolved in a lockfile."""

    name: str
    version: str
    ecosystem: str  # "pypi" or "npm"
    is_direct: bool = False  # True if declared in project manifest, False if transitive
    markers: str | None = None  # raw PEP 508 marker string, if any
    extras: list[str] = field(default_factory=list)  # optional extras requested
    source: str | None = None  # git/url source if not from registry

    def to_dict(self) -> dict:
        result: dict = {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
        }
        if self.is_direct:
            result["is_direct"] = True
        if self.markers:
            result["markers"] = self.markers
        if self.extras:
            result["extras"] = self.extras
        if self.source:
            result["source"] = self.source
        return result


@dataclass
class LockfileParseResult:
    """Result of parsing a lockfile."""

    format: LockfileFormat
    dependencies: list[LockedDependency]
    warnings: list[str] = field(default_factory=list)
    transitive_count: int = 0
    direct_count: int = 0

    def to_dict(self) -> dict:
        return {
            "format": self.format.value,
            "total_packages": len(self.dependencies),
            "direct_count": self.direct_count,
            "transitive_count": self.transitive_count,
            "warnings": self.warnings,
        }


class LockfileParser:
    """Detects and parses lockfiles to extract the resolved dependency graph."""

    @classmethod
    def detect_format(cls, filename: str, content: str) -> LockfileFormat:
        """Detect the lockfile format from filename and content."""
        name = Path(filename).name.lower()
        if name == "uv.lock":
            return LockfileFormat.UV_LOCK
        if name == "poetry.lock":
            return LockfileFormat.POETRY_LOCK
        if name == "package-lock.json":
            return LockfileFormat.PACKAGE_LOCK_JSON
        if name == "yarn.lock":
            return LockfileFormat.YARN_LOCK
        if name == "pipfile.lock":
            return LockfileFormat.PIPFILE_LOCK
        if name.startswith("requirements") and name.endswith(".txt"):
            return LockfileFormat.REQUIREMENTS_TXT
        # Sniff content
        if content.lstrip().startswith("{") and '"lockfileVersion"' in content:
            return LockfileFormat.PACKAGE_LOCK_JSON
        if "__metadata" in content and "version:" in content:
            return LockfileFormat.YARN_LOCK
        if "[[package]]" in content and 'name = "' in content:
            return LockfileFormat.POETRY_LOCK
        if "version = 1" in content and "[[package]]" in content:
            return LockfileFormat.UV_LOCK
        return LockfileFormat.UNKNOWN

    @classmethod
    def parse(cls, content: str, filename: str = "") -> LockfileParseResult:
        """Parse a lockfile and return resolved dependencies."""
        fmt = cls.detect_format(filename, content)
        parsers = {
            LockfileFormat.REQUIREMENTS_TXT: cls._parse_requirements_txt,
            LockfileFormat.UV_LOCK: cls._parse_uv_lock,
            LockfileFormat.POETRY_LOCK: cls._parse_poetry_lock,
            LockfileFormat.PACKAGE_LOCK_JSON: cls._parse_package_lock_json,
            LockfileFormat.YARN_LOCK: cls._parse_yarn_lock,
            LockfileFormat.PIPFILE_LOCK: cls._parse_pipfile_lock,
        }
        parser_fn = parsers.get(fmt)
        if parser_fn is None:
            return LockfileParseResult(
                format=LockfileFormat.UNKNOWN,
                dependencies=[],
                warnings=[f"Unrecognized lockfile format for '{filename}'"],
            )
        try:
            deps, warnings = parser_fn(content)
        except Exception as e:  # noqa: BLE001
            logger.warning("Lockfile parse error for %s: %s", filename, e)
            return LockfileParseResult(
                format=fmt,
                dependencies=[],
                warnings=[f"Parse error: {e}"],
            )
        direct = sum(1 for d in deps if d.is_direct)
        return LockfileParseResult(
            format=fmt,
            dependencies=deps,
            warnings=warnings,
            direct_count=direct,
            transitive_count=len(deps) - direct,
        )

    # -------------------------------------------------------------------------
    # requirements.txt
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_requirements_txt(
        cls, content: str
    ) -> tuple[list[LockedDependency], list[str]]:
        """Parse requirements.txt format.

        Handles:
        - pkg==1.2.3
        - pkg==1.2.3; python_version >= "3.8"  (PEP 508 markers)
        - pkg[extra1,extra2]==1.2.3
        - -r other-requirements.txt  (skipped with warning)
        - # comments
        - -e git+https://...  (skipped with warning)
        """
        deps: list[LockedDependency] = []
        warnings: list[str] = []
        # Matches: name[extras]==version ; markers
        pattern = re.compile(
            r"^(?P<name>[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
            r"(?:\[(?P<extras>[^\]]*)\])?"
            r"\s*==\s*"
            r"(?P<version>[^\s;#]+)"
            r"(?:\s*;\s*(?P<markers>[^#\n]+))?",
            re.MULTILINE,
        )
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-r ") or line.startswith("--requirement"):
                warnings.append(
                    f"Nested requirements file not followed: {line}"
                )
                continue
            if line.startswith("-e ") or line.startswith("--editable"):
                warnings.append(f"Editable/VCS install skipped: {line}")
                continue
            m = pattern.match(line)
            if m:
                extras = [
                    e.strip() for e in (m.group("extras") or "").split(",") if e.strip()
                ]
                deps.append(
                    LockedDependency(
                        name=m.group("name"),
                        version=m.group("version"),
                        ecosystem="pypi",
                        is_direct=True,  # requirements.txt lists direct deps
                        markers=(m.group("markers") or "").strip() or None,
                        extras=extras,
                    )
                )
            elif "==" not in line and line and not line.startswith("-"):
                warnings.append(
                    f"Skipped unpinned requirement: {line.split()[0]}"
                )
        return deps, warnings

    # -------------------------------------------------------------------------
    # uv.lock  (TOML-like, custom format)
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_uv_lock(
        cls, content: str
    ) -> tuple[list[LockedDependency], list[str]]:
        """Parse uv.lock format.

        uv.lock uses TOML-like sections:
            [[package]]
            name = "requests"
            version = "2.31.0"
            source = { registry = "https://pypi.org/simple" }

        Direct deps are listed under [manifest] dependencies.
        """
        warnings: list[str] = []
        deps: list[LockedDependency] = []

        # Collect direct dep names from [manifest] section
        direct_names: set[str] = set()
        manifest_match = re.search(
            r"\[manifest\].*?(?=\n\[|\Z)", content, re.DOTALL
        )
        if manifest_match:
            manifest_text = manifest_match.group(0)
            # dependencies = [...] multi-line array
            dep_array = re.search(
                r"dependencies\s*=\s*\[(.*?)\]", manifest_text, re.DOTALL
            )
            if dep_array:
                for item in re.finditer(
                    r'"([A-Za-z0-9][A-Za-z0-9._-]*)', dep_array.group(1)
                ):
                    direct_names.add(_normalize_pkg_name(item.group(1)))

        # Parse each [[package]] block
        package_blocks = re.split(r"\[\[package\]\]", content)
        for block in package_blocks[1:]:  # skip preamble before first block
            name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
            ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
            if not name_m or not ver_m:
                continue
            name = name_m.group(1)
            version = ver_m.group(1)
            # Check for non-registry source (git, path, url)
            source_m = re.search(r"^source\s*=\s*\{([^}]+)\}", block, re.MULTILINE)
            source = None
            if source_m:
                source_text = source_m.group(1)
                if "registry" not in source_text:
                    source = source_text.strip()
                    warnings.append(
                        f"{name}@{version} installed from non-registry source: {source}"
                    )
            normalized = _normalize_pkg_name(name)
            deps.append(
                LockedDependency(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    is_direct=normalized in direct_names,
                    source=source,
                )
            )
        return deps, warnings

    # -------------------------------------------------------------------------
    # poetry.lock
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_poetry_lock(
        cls, content: str
    ) -> tuple[list[LockedDependency], list[str]]:
        """Parse poetry.lock TOML format.

        Direct packages are identified by "optional = false" in the standard
        poetry lockfile (all non-optional deps are resolved by the solver).
        Since poetry.lock doesn't distinguish direct vs transitive directly,
        we mark everything as is_direct=False and note the limitation.
        """
        warnings: list[str] = [
            "poetry.lock: direct vs transitive distinction requires "
            "cross-referencing pyproject.toml [tool.poetry.dependencies] — "
            "all deps marked as transitive here."
        ]
        deps: list[LockedDependency] = []
        # Split on [[package]] blocks
        blocks = re.split(r"\[\[package\]\]", content)
        for block in blocks[1:]:
            name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
            ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
            if not name_m or not ver_m:
                continue
            name = name_m.group(1)
            version = ver_m.group(1)
            optional_m = re.search(r"^optional\s*=\s*(true|false)", block, re.MULTILINE)
            is_optional = optional_m and optional_m.group(1) == "true"
            extras_m = re.search(r'^extras\s*=\s*\[([^\]]*)\]', block, re.MULTILINE)
            extras = []
            if extras_m:
                extras = [
                    e.strip().strip('"')
                    for e in extras_m.group(1).split(",")
                    if e.strip().strip('"')
                ]
            if is_optional:
                warnings.append(
                    f"{name}@{version} is an optional dep — only present "
                    "if requested via extras"
                )
            deps.append(
                LockedDependency(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    is_direct=False,
                    extras=extras,
                )
            )
        return deps, warnings

    # -------------------------------------------------------------------------
    # package-lock.json (npm v2/v3)
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_package_lock_json(
        cls, content: str
    ) -> tuple[list[LockedDependency], list[str]]:
        """Parse npm package-lock.json v2/v3 format."""
        warnings: list[str] = []
        deps: list[LockedDependency] = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            return deps, [f"JSON parse error: {e}"]

        lock_version = data.get("lockfileVersion", 1)
        if lock_version not in (2, 3):
            warnings.append(
                f"package-lock.json v{lock_version} detected — "
                "only v2/v3 fully supported; attempting best-effort parse."
            )

        # v2/v3: "packages" dict
        packages = data.get("packages", {})
        for pkg_path, pkg_data in packages.items():
            if not pkg_path:  # root package
                continue
            # Extract package name from path:
            # "node_modules/foo" or "node_modules/@scope/foo"
            name = _npm_path_to_name(pkg_path)
            version = pkg_data.get("version", "")
            if not version:
                continue
            is_optional = pkg_data.get("optional", False)
            resolved = pkg_data.get("resolved", "")
            source = None
            if resolved and not resolved.startswith("https://registry.npmjs.org"):
                source = resolved
                warnings.append(
                    f"{name}@{version} resolved from non-registry source: {resolved}"
                )
            if is_optional:
                warnings.append(
                    f"{name}@{version} is an optional npm dep (may not be installed)"
                )
            # Determine if direct: top-level packages key starts with "node_modules/X"
            # (not "node_modules/X/node_modules/Y")
            is_direct = pkg_path.count("node_modules/") == 1
            deps.append(
                LockedDependency(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    is_direct=is_direct,
                    source=source,
                )
            )

        # Fallback to v1 "dependencies" dict
        if not deps and "dependencies" in data:
            warnings.append("Falling back to v1 'dependencies' format")
            cls._parse_npm_v1_deps(
                data.get("dependencies", {}), deps, warnings, depth=0
            )

        return deps, warnings

    @classmethod
    def _parse_npm_v1_deps(
        cls,
        deps_dict: dict,
        deps: list[LockedDependency],
        warnings: list[str],
        depth: int,
    ) -> None:
        """Recursively parse npm v1 nested dependencies."""
        for name, pkg_data in deps_dict.items():
            version = pkg_data.get("version", "")
            if version:
                deps.append(
                    LockedDependency(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        is_direct=(depth == 0),
                    )
                )
            nested = pkg_data.get("dependencies", {})
            if nested:
                cls._parse_npm_v1_deps(nested, deps, warnings, depth + 1)

    # -------------------------------------------------------------------------
    # yarn.lock (classic v1 format)
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_yarn_lock(
        cls, content: str
    ) -> tuple[list[LockedDependency], list[str]]:
        """Parse Yarn classic (v1) yarn.lock format.

        Format:
            package-name@^1.2.3:
              version "1.2.4"
              resolved "https://registry.yarnpkg.com/..."
        """
        warnings: list[str] = []
        deps: list[LockedDependency] = []

        if content.lstrip().startswith("{"):
            # Yarn Berry v2+ uses a different YAML-ish format; simplified parse
            warnings.append(
                "Yarn Berry (v2+) format detected — basic name/version extraction only"
            )
            return cls._parse_yarn_berry(content, warnings)

        # Yarn classic v1
        current_names: list[str] = []
        current_version: str | None = None

        for line in content.splitlines():
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                if current_names and current_version:
                    for name in current_names:
                        deps.append(
                            LockedDependency(
                                name=name,
                                version=current_version,
                                ecosystem="npm",
                                is_direct=False,  # yarn.lock doesn't distinguish
                            )
                        )
                    current_names = []
                    current_version = None
                continue

            if not line.startswith(" "):
                # Entry header: "pkg-name@^1.0.0, pkg-name@~1.0.0:"
                if current_names and current_version:
                    for name in current_names:
                        deps.append(
                            LockedDependency(
                                name=name,
                                version=current_version,
                                ecosystem="npm",
                                is_direct=False,
                            )
                        )
                current_names = []
                current_version = None
                header = line_stripped.rstrip(":")
                for entry in header.split(","):
                    entry = entry.strip()
                    # Remove version specifier: "pkg@^1.0" -> "pkg"
                    at_pos = entry.rfind("@")
                    if at_pos > 0:
                        name = entry[:at_pos]
                    else:
                        name = entry
                    name = name.strip("\"'")
                    if name:
                        current_names.append(name)
            else:
                version_m = re.match(r'\s+version\s+"([^"]+)"', line)
                if version_m:
                    current_version = version_m.group(1)
                resolved_m = re.match(r'\s+resolved\s+"([^"]+)"', line)
                if resolved_m:
                    resolved = resolved_m.group(1)
                    known = ("registry.yarnpkg.com", "registry.npmjs.org")
                    if not any(r in resolved for r in known):
                        for name in current_names:
                            warnings.append(
                                f"{name} resolved from non-registry source: {resolved}"
                            )

        # Flush last block
        if current_names and current_version:
            for name in current_names:
                deps.append(
                    LockedDependency(
                        name=name,
                        version=current_version,
                        ecosystem="npm",
                        is_direct=False,
                    )
                )

        if not deps:
            warnings.append("No pinned packages found in yarn.lock")
        else:
            warnings.append(
                "yarn.lock: direct vs transitive distinction requires "
                "cross-referencing package.json — all deps marked as transitive."
            )
        return deps, warnings

    @classmethod
    def _parse_yarn_berry(
        cls, content: str, warnings: list[str]
    ) -> tuple[list[LockedDependency], list[str]]:
        """Simplified parse for Yarn Berry YAML-ish format."""
        deps: list[LockedDependency] = []
        for m in re.finditer(
            r'"?(?P<name>@?[a-z0-9][a-z0-9._-]*/[a-z0-9._-]+|[a-z0-9][a-z0-9._-]*)'
            r'@[^"]+?"?\s*:\s*\n\s+version:\s+(?P<version>[^\n]+)',
            content,
        ):
            deps.append(
                LockedDependency(
                    name=m.group("name"),
                    version=m.group("version").strip(),
                    ecosystem="npm",
                    is_direct=False,
                )
            )
        return deps, warnings

    # -------------------------------------------------------------------------
    # Pipfile.lock
    # -------------------------------------------------------------------------
    @classmethod
    def _parse_pipfile_lock(
        cls, content: str
    ) -> tuple[list[LockedDependency], list[str]]:
        """Parse Pipfile.lock JSON format."""
        warnings: list[str] = []
        deps: list[LockedDependency] = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            return deps, [f"JSON parse error: {e}"]

        for section in ("default", "develop"):
            section_data = data.get(section, {})
            for name, pkg_data in section_data.items():
                version_str = pkg_data.get("version", "")
                # Pipfile.lock uses "==1.2.3" format
                version = version_str.lstrip("=")
                if not version:
                    markers = pkg_data.get("markers", None)
                    warnings.append(
                        f"{name} has no pinned version in Pipfile.lock"
                    )
                    continue
                markers = pkg_data.get("markers", None)
                index = pkg_data.get("index", "")
                source = None
                if not index or index not in ("pypi", ""):
                    ref = pkg_data.get("ref", pkg_data.get("git", ""))
                    if ref:
                        source = ref
                        warnings.append(
                            f"{name}@{version} installed from VCS/custom source"
                        )
                deps.append(
                    LockedDependency(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        is_direct=True,  # Pipfile.lock only contains direct + resolved
                        markers=markers,
                        source=source,
                    )
                )
        return deps, warnings


def _normalize_pkg_name(name: str) -> str:
    """Normalize package name per PEP 503.

    Lowercases and collapses dashes/underscores/dots to a single dash.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def _npm_path_to_name(path: str) -> str:
    """Convert node_modules path to package name.

    Examples:
        node_modules/lodash -> lodash
        node_modules/@scope/pkg -> @scope/pkg
        node_modules/a/node_modules/@scope/b -> @scope/b
    """
    parts = path.split("node_modules/")
    last = parts[-1].rstrip("/")
    # Scoped package: @scope/pkg
    if last.startswith("@") and "/" in last:
        slash = last.index("/")
        scope = last[:slash]
        rest = last[slash + 1:].split("/")[0]
        return f"{scope}/{rest}"
    return last.split("/")[0]
