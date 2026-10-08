"""Shared utilities."""

from .io import is_read_only_mode
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
