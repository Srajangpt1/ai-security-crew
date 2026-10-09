"""PEP 508 environment marker evaluator.

Evaluates dependency markers like:
    python_version >= "3.8"
    sys_platform == "linux"
    extra == "dev"
    python_version >= "3.8" and sys_platform != "win32"

Used to determine whether a conditional dependency is actually
active in the current (or a target) environment, so we can filter
the lockfile to what's *really* loaded at runtime.

Reference: https://peps.python.org/pep-0508/#environment-markers
"""

from __future__ import annotations

import logging
import platform
import re
import sys
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class EnvironmentContext:
    """Runtime environment for evaluating PEP 508 markers.

    Defaults to the current interpreter's environment.
    Pass explicit values to evaluate for a *target* environment
    (e.g. a container running Python 3.11 on linux/amd64).
    """

    python_version: str = field(
        default_factory=lambda: f"{sys.version_info.major}.{sys.version_info.minor}"
    )
    python_full_version: str = field(
        default_factory=lambda: (
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        )
    )
    python_version_tuple: tuple[int, ...] = field(
        default_factory=lambda: sys.version_info[:3]
    )
    os_name: str = field(default_factory=lambda: platform.system().lower())
    sys_platform: str = field(
        default_factory=lambda: sys.platform
    )
    platform_machine: str = field(
        default_factory=lambda: platform.machine()
    )
    platform_python_implementation: str = field(
        default_factory=lambda: platform.python_implementation()
    )
    implementation_name: str = field(
        default_factory=lambda: platform.python_implementation().lower()
    )
    extras: list[str] = field(default_factory=list)

    @classmethod
    def for_container(
        cls,
        python_version: str = "3.11",
        sys_platform: str = "linux",
        platform_machine: str = "x86_64",
    ) -> EnvironmentContext:
        """Create an environment context representing a typical Linux container."""
        major, minor = python_version.split(".")[:2]
        return cls(
            python_version=f"{major}.{minor}",
            python_full_version=f"{major}.{minor}.0",
            python_version_tuple=(int(major), int(minor), 0),
            os_name="posix",
            sys_platform=sys_platform,
            platform_machine=platform_machine,
            platform_python_implementation="CPython",
            implementation_name="cpython",
        )

    def to_marker_env(self) -> dict[str, str]:
        """Return the marker variable dict for evaluation."""
        return {
            "python_version": self.python_version,
            "python_full_version": self.python_full_version,
            "os_name": self.os_name,
            "sys_platform": self.sys_platform,
            "platform_machine": self.platform_machine,
            "platform_python_implementation": self.platform_python_implementation,
            "implementation_name": self.implementation_name,
            "platform_release": "",
            "platform_system": self.os_name.capitalize(),
            "platform_version": "",
            "extra": "",  # overridden in evaluate_for_extras
        }


@dataclass
class MarkerEvalResult:
    """Result of evaluating a PEP 508 marker."""

    marker: str
    active: bool  # True if this dep is loaded in the target environment
    reason: str
    # When active is uncertain (e.g. dynamic extras), flag it
    uncertain: bool = False

    def to_dict(self) -> dict:
        result: dict = {
            "marker": self.marker,
            "active": self.active,
            "reason": self.reason,
        }
        if self.uncertain:
            result["uncertain"] = True
        return result


class EnvMarkerEvaluator:
    """Evaluates PEP 508 environment markers against a runtime context.

    Handles:
    - Comparison operators: ==, !=, <, <=, >, >=, ~=, in, not in
    - Boolean operators: and, or, not
    - All standard PEP 508 marker variables
    - Version comparisons (semver-aware)
    - Extra markers (with known extras list)
    """

    # Marker variables that take string (non-version) values
    _STRING_VARS = frozenset(
        {
            "os_name",
            "sys_platform",
            "platform_machine",
            "platform_python_implementation",
            "implementation_name",
            "platform_release",
            "platform_system",
            "platform_version",
            "extra",
        }
    )

    # Marker variables that take version values
    _VERSION_VARS = frozenset(
        {
            "python_version",
            "python_full_version",
            "implementation_version",
        }
    )

    def evaluate(
        self,
        marker: str,
        env: EnvironmentContext | None = None,
    ) -> MarkerEvalResult:
        """Evaluate a PEP 508 marker string.

        Returns MarkerEvalResult with active=True if the dep should
        be installed in the given environment.
        """
        if not marker or not marker.strip():
            return MarkerEvalResult(
                marker=marker, active=True, reason="No marker — always active"
            )
        env = env or EnvironmentContext()
        env_dict = env.to_marker_env()

        # Check for extra marker — needs special handling
        has_extra = "extra" in marker
        if has_extra and not env.extras:
            return MarkerEvalResult(
                marker=marker,
                active=False,
                reason=(
                    "Marker references 'extra' but no extras were requested — "
                    "optional dep not active. Pass extras= to check specific extras."
                ),
                uncertain=False,
            )
        if has_extra and env.extras:
            # Evaluate for each requested extra; active if any match
            for extra_val in env.extras:
                env_dict["extra"] = extra_val
                try:
                    result = self._eval_expr(marker, env_dict)
                    if result:
                        return MarkerEvalResult(
                            marker=marker,
                            active=True,
                            reason=f"Active with extra='{extra_val}'",
                        )
                except Exception:  # noqa: BLE001, S110
                    logger.debug("Marker eval failed for extra=%r", extra_val)
            return MarkerEvalResult(
                marker=marker,
                active=False,
                reason=f"Not active for extras {env.extras}",
            )

        try:
            result = self._eval_expr(marker, env_dict)
            reason = self._explain(marker, env_dict, result)
            return MarkerEvalResult(marker=marker, active=result, reason=reason)
        except Exception as e:  # noqa: BLE001
            reason = f"Could not evaluate marker: {e} — assuming active (conservative)"
            return MarkerEvalResult(
                marker=marker,
                active=True,  # conservative: assume active if we can't evaluate
                reason=reason,
                uncertain=True,
            )

    def filter_active(
        self,
        deps: list,  # list[LockedDependency]
        env: EnvironmentContext | None = None,
    ) -> tuple[list, list[str]]:
        """Filter a list of LockedDependency to those active in the environment.

        Returns (active_deps, skipped_reasons).
        """
        from mcp_security_review.providers.sca.lockfile import LockedDependency

        env = env or EnvironmentContext()
        active: list[LockedDependency] = []
        skipped: list[str] = []

        for dep in deps:
            if not dep.markers:
                active.append(dep)
                continue
            result = self.evaluate(dep.markers, env)
            if result.active:
                active.append(dep)
            else:
                skipped.append(
                    f"{dep.name}@{dep.version} skipped: {result.reason}"
                )

        return active, skipped

    # -------------------------------------------------------------------------
    # Internal evaluation
    # -------------------------------------------------------------------------
    def _eval_expr(self, expr: str, env: dict[str, str]) -> bool:
        """Recursively evaluate a marker expression."""
        expr = expr.strip()

        # Handle parenthesized groups
        expr = self._strip_outer_parens(expr)

        # Boolean operators (lowest precedence first)
        for op in (" or ", " and "):
            parts = self._split_on_boolean(expr, op.strip())
            if parts:
                results = [self._eval_expr(p, env) for p in parts]
                if op.strip() == "or":
                    return any(results)
                else:
                    return all(results)

        # "not" prefix
        if expr.lower().startswith("not "):
            return not self._eval_expr(expr[4:], env)

        # Single comparison
        return self._eval_comparison(expr, env)

    def _split_on_boolean(self, expr: str, op: str) -> list[str] | None:
        """Split expression on boolean operator, respecting parentheses depth."""
        depth = 0
        op_lower = f" {op} "
        i = 0
        positions = []
        while i < len(expr):
            ch = expr[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif depth == 0:
                if expr[i : i + len(op_lower)].lower() == op_lower:
                    positions.append(i)
                    i += len(op_lower)
                    continue
            i += 1
        if not positions:
            return None
        parts = []
        prev = 0
        for pos in positions:
            parts.append(expr[prev:pos].strip())
            prev = pos + len(op_lower)
        parts.append(expr[prev:].strip())
        return parts

    def _strip_outer_parens(self, expr: str) -> str:
        """Remove matching outer parentheses if they wrap the whole expression."""
        while expr.startswith("(") and expr.endswith(")"):
            # Make sure the opening paren matches the closing paren
            depth = 0
            for i, ch in enumerate(expr):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                if depth == 0 and i < len(expr) - 1:
                    return expr  # inner close before end — not wrapping parens
            expr = expr[1:-1].strip()
        return expr

    def _eval_comparison(self, expr: str, env: dict[str, str]) -> bool:
        """Evaluate a single comparison like 'python_version >= "3.8"'."""
        # Operator order matters: longer first to avoid partial matches
        operators = [
            "not in", "in", "~=", "!=", "==", "<=", ">=", "<", ">",
        ]
        for op in operators:
            # Find op not inside quotes
            idx = self._find_op(expr, op)
            if idx >= 0:
                lhs = expr[:idx].strip()
                rhs = expr[idx + len(op):].strip().strip("\"'")
                lhs_val = env.get(lhs, lhs.strip("\"'"))
                version_compare = lhs in self._VERSION_VARS
                return self._compare(lhs_val, op, rhs, version_compare)
        msg = f"Cannot parse marker comparison: {expr!r}"
        raise ValueError(msg)

    def _find_op(self, expr: str, op: str) -> int:
        """Find operator position, ignoring quoted strings."""
        in_quote = None
        i = 0
        while i < len(expr):
            ch = expr[i]
            if ch in ('"', "'"):
                if in_quote == ch:
                    in_quote = None
                elif in_quote is None:
                    in_quote = ch
            elif in_quote is None:
                if expr[i : i + len(op)] == op:
                    # Make sure it's not part of a longer operator
                    before = expr[i - 1] if i > 0 else " "
                    after = expr[i + len(op)] if i + len(op) < len(expr) else " "
                    if op in ("in", "not in"):
                        # Must be surrounded by spaces
                        if before == " " and after == " ":
                            return i
                    elif op in ("<", ">"):
                        # Avoid matching <= or >=
                        if after not in ("=", "<", ">"):
                            return i
                    else:
                        return i
            i += 1
        return -1

    def _compare(
        self,
        lhs: str,
        op: str,
        rhs: str,
        is_version: bool,  # noqa: FBT001
    ) -> bool:
        """Perform the actual comparison."""
        if op == "in":
            return lhs in rhs
        if op == "not in":
            return lhs not in rhs

        if is_version:
            try:
                lhs_v = _parse_version(lhs)
                rhs_v = _parse_version(rhs)
                if op == "==":
                    return lhs_v == rhs_v
                if op == "!=":
                    return lhs_v != rhs_v
                if op == "<":
                    return lhs_v < rhs_v
                if op == "<=":
                    return lhs_v <= rhs_v
                if op == ">":
                    return lhs_v > rhs_v
                if op == ">=":
                    return lhs_v >= rhs_v
                if op == "~=":
                    # Compatible release: >= rhs, == rhs.*
                    prefix = len(rhs_v) - 1
                    return lhs_v >= rhs_v and lhs_v[:prefix] == rhs_v[:prefix]
            except (ValueError, IndexError):
                pass  # Fall through to string comparison

        lhs_s = lhs.lower()
        rhs_s = rhs.lower()
        if op == "==":
            return lhs_s == rhs_s
        if op == "!=":
            return lhs_s != rhs_s
        if op == "<":
            return lhs_s < rhs_s
        if op == "<=":
            return lhs_s <= rhs_s
        if op == ">":
            return lhs_s > rhs_s
        if op == ">=":
            return lhs_s >= rhs_s
        return False

    def _explain(self, marker: str, env: dict[str, str], result: bool) -> str:  # noqa: FBT001
        """Generate a human-readable explanation of the evaluation."""
        status = "active" if result else "not active"
        # Extract the key variable for a simple one-liner
        var_match = re.search(
            r"(python_version|sys_platform|platform_machine|os_name|extra)\s*"
            r"([=!<>~]+|not in|in)\s*['\"]([^'\"]+)['\"]",
            marker,
        )
        if var_match:
            var, op, val = var_match.groups()
            env_val = env.get(var, "?")
            return f"{status}: {var}={env_val!r} {op} {val!r}"
        return f"{status} in target environment"


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple of ints."""
    # Strip pre/post/dev suffixes for comparison
    clean = re.sub(r"[a-zA-Z+].*$", "", version_str)
    parts = clean.split(".")
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result) if result else (0,)
