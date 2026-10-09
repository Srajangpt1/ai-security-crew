"""SCA (Software Composition Analysis) providers.

Package registry verification and vulnerability scanning via OSV.dev.
"""

from .lockfile import LockfileParser, LockedDependency, LockfileParseResult, LockfileFormat
from .markers import EnvMarkerEvaluator, EnvironmentContext, MarkerEvalResult
from .osv import OSVScanner
from .registry import PackageRegistry

__all__ = [
    "OSVScanner",
    "PackageRegistry",
    "LockfileParser",
    "LockedDependency",
    "LockfileParseResult",
    "LockfileFormat",
    "EnvMarkerEvaluator",
    "EnvironmentContext",
    "MarkerEvalResult",
]
