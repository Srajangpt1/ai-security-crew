"""Tests for LockfileParser — runtime dependency graph resolution."""

import pytest

from mcp_security_review.providers.sca.lockfile import (
    LockfileFormat,
    LockfileParser,
    LockedDependency,
    _normalize_pkg_name,
    _npm_path_to_name,
)


class TestFormatDetection:
    def test_detect_uv_lock_by_name(self) -> None:
        assert LockfileParser.detect_format("uv.lock", "") == LockfileFormat.UV_LOCK

    def test_detect_poetry_lock_by_name(self) -> None:
        assert LockfileParser.detect_format("poetry.lock", "") == LockfileFormat.POETRY_LOCK

    def test_detect_package_lock_by_name(self) -> None:
        assert (
            LockfileParser.detect_format("package-lock.json", "")
            == LockfileFormat.PACKAGE_LOCK_JSON
        )

    def test_detect_yarn_lock_by_name(self) -> None:
        assert LockfileParser.detect_format("yarn.lock", "") == LockfileFormat.YARN_LOCK

    def test_detect_pipfile_lock_by_name(self) -> None:
        assert LockfileParser.detect_format("Pipfile.lock", "") == LockfileFormat.PIPFILE_LOCK

    def test_detect_requirements_txt(self) -> None:
        assert (
            LockfileParser.detect_format("requirements.txt", "")
            == LockfileFormat.REQUIREMENTS_TXT
        )

    def test_detect_requirements_dev_txt(self) -> None:
        assert (
            LockfileParser.detect_format("requirements-dev.txt", "")
            == LockfileFormat.REQUIREMENTS_TXT
        )

    def test_detect_package_lock_by_content(self) -> None:
        content = '{"lockfileVersion": 2, "packages": {}}'
        assert (
            LockfileParser.detect_format("lockfile", content)
            == LockfileFormat.PACKAGE_LOCK_JSON
        )

    def test_detect_poetry_lock_by_content(self) -> None:
        content = '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
        assert LockfileParser.detect_format("lockfile", content) == LockfileFormat.POETRY_LOCK

    def test_unknown_format(self) -> None:
        assert LockfileParser.detect_format("random.file", "nothing") == LockfileFormat.UNKNOWN


class TestRequirementsTxtParser:
    def test_simple_pinned(self) -> None:
        content = "requests==2.31.0\nhttpx==0.24.0\n"
        result = LockfileParser.parse(content, "requirements.txt")
        assert result.format == LockfileFormat.REQUIREMENTS_TXT
        assert len(result.dependencies) == 2
        names = {d.name for d in result.dependencies}
        assert names == {"requests", "httpx"}

    def test_version_extracted(self) -> None:
        content = "pyjwt==2.4.0\n"
        result = LockfileParser.parse(content, "requirements.txt")
        assert result.dependencies[0].version == "2.4.0"

    def test_env_marker_preserved(self) -> None:
        content = 'pywin32==305; sys_platform == "win32"\n'
        result = LockfileParser.parse(content, "requirements.txt")
        assert len(result.dependencies) == 1
        dep = result.dependencies[0]
        assert dep.name == "pywin32"
        assert dep.markers == 'sys_platform == "win32"'

    def test_extras_extracted(self) -> None:
        content = "requests[security]==2.31.0\n"
        result = LockfileParser.parse(content, "requirements.txt")
        assert result.dependencies[0].extras == ["security"]

    def test_comments_ignored(self) -> None:
        content = "# This is a comment\nrequests==2.31.0\n"
        result = LockfileParser.parse(content, "requirements.txt")
        assert len(result.dependencies) == 1

    def test_unpinned_generates_warning(self) -> None:
        content = "requests>=2.0\n"
        result = LockfileParser.parse(content, "requirements.txt")
        assert len(result.dependencies) == 0
        assert any("unpinned" in w for w in result.warnings)

    def test_nested_requirements_warning(self) -> None:
        content = "-r base.txt\nrequests==2.31.0\n"
        result = LockfileParser.parse(content, "requirements.txt")
        assert any("Nested requirements" in w for w in result.warnings)

    def test_all_direct(self) -> None:
        content = "requests==2.31.0\nhttpx==0.24.0\n"
        result = LockfileParser.parse(content, "requirements.txt")
        assert all(d.is_direct for d in result.dependencies)
        assert result.direct_count == 2

    def test_ecosystem_is_pypi(self) -> None:
        content = "requests==2.31.0\n"
        result = LockfileParser.parse(content, "requirements.txt")
        assert result.dependencies[0].ecosystem == "pypi"


class TestUvLockParser:
    def _make_uv_lock(self, packages: list[tuple[str, str]]) -> str:
        lines = ["version = 1\n\n[manifest]\ndependencies = ["]
        lines.append(f'  "{packages[0][0]}",')
        lines.append("]\n")
        for name, version in packages:
            lines.append("[[package]]")
            lines.append(f'name = "{name}"')
            lines.append(f'version = "{version}"')
            lines.append('source = { registry = "https://pypi.org/simple" }\n')
        return "\n".join(lines)

    def test_parses_packages(self) -> None:
        content = self._make_uv_lock([("requests", "2.31.0"), ("httpx", "0.24.0")])
        result = LockfileParser.parse(content, "uv.lock")
        assert result.format == LockfileFormat.UV_LOCK
        assert len(result.dependencies) == 2

    def test_version_extracted(self) -> None:
        content = self._make_uv_lock([("pyjwt", "2.4.0")])
        result = LockfileParser.parse(content, "uv.lock")
        assert result.dependencies[0].version == "2.4.0"

    def test_non_registry_source_warning(self) -> None:
        content = (
            "version = 1\n\n[[package]]\n"
            'name = "mypkg"\nversion = "1.0.0"\n'
            'source = { git = "https://github.com/foo/bar.git#abc123" }\n'
        )
        result = LockfileParser.parse(content, "uv.lock")
        assert any("non-registry source" in w for w in result.warnings)

    def test_ecosystem_is_pypi(self) -> None:
        content = self._make_uv_lock([("requests", "2.31.0")])
        result = LockfileParser.parse(content, "uv.lock")
        assert result.dependencies[0].ecosystem == "pypi"


class TestPoetryLockParser:
    def _make_poetry_lock(self, packages: list[tuple[str, str]]) -> str:
        blocks = []
        for name, version in packages:
            blocks.append(
                f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
                f'optional = false\npython-versions = ">=3.8"\n'
            )
        return "\n".join(blocks)

    def test_parses_packages(self) -> None:
        content = self._make_poetry_lock([("requests", "2.31.0"), ("httpx", "0.24.0")])
        result = LockfileParser.parse(content, "poetry.lock")
        assert result.format == LockfileFormat.POETRY_LOCK
        assert len(result.dependencies) == 2

    def test_optional_dep_warning(self) -> None:
        content = (
            '[[package]]\nname = "cryptography"\nversion = "41.0.0"\n'
            "optional = true\n"
        )
        result = LockfileParser.parse(content, "poetry.lock")
        assert any("optional" in w for w in result.warnings)

    def test_direct_transitive_limitation_warning(self) -> None:
        content = self._make_poetry_lock([("requests", "2.31.0")])
        result = LockfileParser.parse(content, "poetry.lock")
        assert any("transitive" in w for w in result.warnings)


class TestPackageLockJsonParser:
    def _make_package_lock(self, packages: dict[str, str]) -> str:
        import json
        pkgs: dict[str, dict] = {}
        for name, version in packages.items():
            pkgs[f"node_modules/{name}"] = {
                "version": version,
                "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
            }
        return json.dumps({"lockfileVersion": 2, "packages": pkgs})

    def test_parses_packages(self) -> None:
        content = self._make_package_lock({"lodash": "4.17.21", "express": "4.18.2"})
        result = LockfileParser.parse(content, "package-lock.json")
        assert result.format == LockfileFormat.PACKAGE_LOCK_JSON
        assert len(result.dependencies) == 2

    def test_ecosystem_is_npm(self) -> None:
        content = self._make_package_lock({"lodash": "4.17.21"})
        result = LockfileParser.parse(content, "package-lock.json")
        assert result.dependencies[0].ecosystem == "npm"

    def test_direct_package_detected(self) -> None:
        content = self._make_package_lock({"lodash": "4.17.21"})
        result = LockfileParser.parse(content, "package-lock.json")
        assert result.dependencies[0].is_direct is True

    def test_transitive_detected(self) -> None:
        import json
        pkgs = {
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/express/node_modules/qs": {"version": "6.11.0"},
        }
        content = json.dumps({"lockfileVersion": 2, "packages": pkgs})
        result = LockfileParser.parse(content, "package-lock.json")
        direct = [d for d in result.dependencies if d.is_direct]
        transitive = [d for d in result.dependencies if not d.is_direct]
        assert len(direct) == 1
        assert len(transitive) == 1

    def test_non_registry_source_flagged(self) -> None:
        import json
        pkgs = {
            "node_modules/mypkg": {
                "version": "1.0.0",
                "resolved": "https://github.com/foo/bar/tarball/abc123",
            }
        }
        content = json.dumps({"lockfileVersion": 2, "packages": pkgs})
        result = LockfileParser.parse(content, "package-lock.json")
        assert any("non-registry" in w for w in result.warnings)

    def test_invalid_json_returns_warning(self) -> None:
        result = LockfileParser.parse("not json", "package-lock.json")
        assert any("parse error" in w.lower() for w in result.warnings)


class TestYarnLockParser:
    def test_simple_yarn_v1(self) -> None:
        content = (
            "# yarn lockfile v1\n\n"
            'lodash@^4.17.0:\n  version "4.17.21"\n'
            '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"\n\n'
        )
        result = LockfileParser.parse(content, "yarn.lock")
        assert result.format == LockfileFormat.YARN_LOCK
        assert len(result.dependencies) == 1
        assert result.dependencies[0].version == "4.17.21"
        assert result.dependencies[0].name == "lodash"

    def test_scoped_package(self) -> None:
        content = (
            '"@types/node@^18.0.0":\n  version "18.11.0"\n'
            '  resolved "https://registry.yarnpkg.com/@types/node/-/node-18.11.0.tgz"\n\n'
        )
        result = LockfileParser.parse(content, "yarn.lock")
        assert result.dependencies[0].name == "@types/node"

    def test_non_registry_source_flagged(self) -> None:
        content = (
            "mypkg@github:org/repo:\n  version \"1.0.0\"\n"
            "  resolved \"https://github.com/org/repo/tarball/abc#abc\"\n\n"
        )
        result = LockfileParser.parse(content, "yarn.lock")
        assert any("non-registry" in w for w in result.warnings)


class TestPipfileLockParser:
    def test_parses_default_deps(self) -> None:
        import json
        data = {
            "_meta": {},
            "default": {
                "requests": {"version": "==2.31.0", "index": "pypi"},
                "httpx": {"version": "==0.24.0", "index": "pypi"},
            },
            "develop": {},
        }
        result = LockfileParser.parse(json.dumps(data), "Pipfile.lock")
        assert result.format == LockfileFormat.PIPFILE_LOCK
        assert len(result.dependencies) == 2

    def test_markers_preserved(self) -> None:
        import json
        data = {
            "default": {
                "pywin32": {
                    "version": "==305",
                    "markers": 'sys_platform == "win32"',
                    "index": "pypi",
                }
            },
            "develop": {},
        }
        result = LockfileParser.parse(json.dumps(data), "Pipfile.lock")
        assert result.dependencies[0].markers == 'sys_platform == "win32"'


class TestHelpers:
    def test_normalize_pkg_name(self) -> None:
        assert _normalize_pkg_name("PyJWT") == "pyjwt"
        assert _normalize_pkg_name("my-package") == "my-package"
        assert _normalize_pkg_name("my_package") == "my-package"
        assert _normalize_pkg_name("my.package") == "my-package"
        assert _normalize_pkg_name("My--Package") == "my-package"

    def test_npm_path_to_name_simple(self) -> None:
        assert _npm_path_to_name("node_modules/lodash") == "lodash"

    def test_npm_path_to_name_scoped(self) -> None:
        assert _npm_path_to_name("node_modules/@scope/pkg") == "@scope/pkg"

    def test_npm_path_to_name_nested(self) -> None:
        assert _npm_path_to_name("node_modules/a/node_modules/b") == "b"

    def test_npm_path_to_name_scoped_nested(self) -> None:
        assert _npm_path_to_name("node_modules/express/node_modules/@scope/pkg") == "@scope/pkg"
