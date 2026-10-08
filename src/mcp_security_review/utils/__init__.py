"""Shared utilities.

Only dependency-light helpers are re-exported here so the core package imports
without the optional Atlassian extra. Atlassian-specific helpers (``date``,
``oauth``, ``ssl``, ``urls``, ``decorators``) are imported from their modules.
"""

from .io import is_read_only_mode

# Export lifecycle utilities
from .lifecycle import (
    ensure_clean_exit,
    setup_signal_handlers,
)
from .logging import setup_logging

__all__ = [
    "is_read_only_mode",
    "setup_logging",
    "setup_signal_handlers",
    "ensure_clean_exit",
]
