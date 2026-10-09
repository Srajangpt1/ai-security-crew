"""Tests for EnvMarkerEvaluator — PEP 508 marker evaluation."""

import pytest

from mcp_security_review.providers.sca.lockfile import LockedDependency
from mcp_security_review.providers.sca.markers import (
    EnvMarkerEvaluator,
    EnvironmentContext,
    _parse_version,
)


class TestVersionParsing:
    def test_simple(self) -> None:
        assert _parse_version("3.11") == (3, 11)

    def test_full(self) -> None:
        assert _parse_version("3.11.2") == (3, 11, 2)

    def test_with_suffix(self) -> None:
        assert _parse_version("3.8.0b1") == (3, 8, 0)

    def test_empty(self) -> None:
        assert _parse_version("") == (0,)


class TestEnvironmentContext:
    def test_defaults_to_current_env(self) -> None:
        import sys
        env = EnvironmentContext()
        major, minor = env.python_version.split(".")
        assert int(major) == sys.version_info.major
        assert int(minor) == sys.version_info.minor

    def test_for_container(self) -> None:
        env = EnvironmentContext.for_container(
            python_version="3.11",
            sys_platform="linux",
            platform_machine="aarch64",
        )
        assert env.python_version == "3.11"
        assert env.sys_platform == "linux"
        assert env.platform_machine == "aarch64"
        assert env.os_name == "posix"

    def test_to_marker_env(self) -> None:
        env = EnvironmentContext.for_container("3.11", "linux")
        d = env.to_marker_env()
        assert d["python_version"] == "3.11"
        assert d["sys_platform"] == "linux"
        assert "extra" in d


class TestEnvMarkerEvaluator:
    def setup_method(self) -> None:
        self.ev = EnvMarkerEvaluator()
        self.linux_311 = EnvironmentContext.for_container("3.11", "linux")
        self.win_38 = EnvironmentContext.for_container("3.8", "win32")

    # ------ Empty marker ------
    def test_empty_marker_always_active(self) -> None:
        r = self.ev.evaluate("", self.linux_311)
        assert r.active is True

    def test_none_marker_active(self) -> None:
        r = self.ev.evaluate(None, self.linux_311)  # type: ignore[arg-type]
        assert r.active is True

    # ------ python_version comparisons ------
    def test_python_version_gte_active(self) -> None:
        r = self.ev.evaluate('python_version >= "3.8"', self.linux_311)
        assert r.active is True

    def test_python_version_gte_inactive(self) -> None:
        r = self.ev.evaluate('python_version >= "3.12"', self.linux_311)
        assert r.active is False

    def test_python_version_eq(self) -> None:
        r = self.ev.evaluate('python_version == "3.11"', self.linux_311)
        assert r.active is True

    def test_python_version_lt(self) -> None:
        r = self.ev.evaluate('python_version < "3.10"', self.linux_311)
        assert r.active is False

    def test_python_version_ne(self) -> None:
        r = self.ev.evaluate('python_version != "3.11"', self.linux_311)
        assert r.active is False

    # ------ sys_platform ------
    def test_sys_platform_eq_linux(self) -> None:
        r = self.ev.evaluate('sys_platform == "linux"', self.linux_311)
        assert r.active is True

    def test_sys_platform_eq_win32_inactive_on_linux(self) -> None:
        r = self.ev.evaluate('sys_platform == "win32"', self.linux_311)
        assert r.active is False

    def test_sys_platform_ne(self) -> None:
        r = self.ev.evaluate('sys_platform != "win32"', self.linux_311)
        assert r.active is True

    # ------ Boolean combinations ------
    def test_and_both_true(self) -> None:
        r = self.ev.evaluate(
            'python_version >= "3.8" and sys_platform == "linux"',
            self.linux_311,
        )
        assert r.active is True

    def test_and_one_false(self) -> None:
        r = self.ev.evaluate(
            'python_version >= "3.8" and sys_platform == "win32"',
            self.linux_311,
        )
        assert r.active is False

    def test_or_first_true(self) -> None:
        r = self.ev.evaluate(
            'sys_platform == "linux" or sys_platform == "win32"',
            self.linux_311,
        )
        assert r.active is True

    def test_or_both_false(self) -> None:
        r = self.ev.evaluate(
            'sys_platform == "darwin" or sys_platform == "win32"',
            self.linux_311,
        )
        assert r.active is False

    # ------ Parenthesized expressions ------
    def test_parenthesized(self) -> None:
        r = self.ev.evaluate(
            '(python_version >= "3.8") and (sys_platform == "linux")',
            self.linux_311,
        )
        assert r.active is True

    # ------ extra markers ------
    def test_extra_no_extras_requested(self) -> None:
        r = self.ev.evaluate('extra == "security"', self.linux_311)
        assert r.active is False
        assert "optional" in r.reason.lower() or "extras" in r.reason.lower()

    def test_extra_with_matching_extra(self) -> None:
        env = EnvironmentContext.for_container("3.11", "linux")
        env.extras = ["security"]
        r = self.ev.evaluate('extra == "security"', env)
        assert r.active is True

    def test_extra_with_non_matching_extra(self) -> None:
        env = EnvironmentContext.for_container("3.11", "linux")
        env.extras = ["async"]
        r = self.ev.evaluate('extra == "security"', env)
        assert r.active is False

    # ------ in / not in ------
    def test_in_operator(self) -> None:
        r = self.ev.evaluate('sys_platform in "linux darwin"', self.linux_311)
        assert r.active is True

    def test_not_in_operator(self) -> None:
        r = self.ev.evaluate('sys_platform not in "win32 darwin"', self.linux_311)
        assert r.active is True

    # ------ Windows-specific deps on Linux container ------
    def test_windows_dep_inactive_on_linux(self) -> None:
        r = self.ev.evaluate('sys_platform == "win32"', self.linux_311)
        assert r.active is False
        assert "not active" in r.reason or "active" in r.reason

    def test_windows_dep_active_on_windows(self) -> None:
        r = self.ev.evaluate('sys_platform == "win32"', self.win_38)
        assert r.active is True

    # ------ filter_active ------
    def test_filter_active_removes_inactive(self) -> None:
        deps = [
            LockedDependency(
                name="pywin32", version="305", ecosystem="pypi",
                markers='sys_platform == "win32"'
            ),
            LockedDependency(name="requests", version="2.31.0", ecosystem="pypi"),
        ]
        active, skipped = self.ev.filter_active(deps, self.linux_311)
        assert len(active) == 1
        assert active[0].name == "requests"
        assert len(skipped) == 1
        assert "pywin32" in skipped[0]

    def test_filter_active_keeps_all_when_matching(self) -> None:
        deps = [
            LockedDependency(
                name="requests", version="2.31.0", ecosystem="pypi",
                markers='python_version >= "3.8"'
            ),
        ]
        active, skipped = self.ev.filter_active(deps, self.linux_311)
        assert len(active) == 1
        assert len(skipped) == 0

    def test_filter_active_no_markers(self) -> None:
        deps = [
            LockedDependency(name="requests", version="2.31.0", ecosystem="pypi"),
        ]
        active, skipped = self.ev.filter_active(deps, self.linux_311)
        assert len(active) == 1
        assert len(skipped) == 0
