"""Helpers shared by the tools that read the threat library."""

import logging

from mcp_security_review.errors import tool_error
from mcp_security_review.library import LibraryError, UnknownComponentError
from mcp_security_review.providers.attack import (
    AttackIndex,
    ensure_attack_index_background,
)

logger = logging.getLogger("mcp-security-review.servers.library")


def split_ids(value: str) -> list[str]:
    """Split a comma- or space-separated list of ids, keeping order.

    Ids are lowercased and underscores become hyphens, so ``File_Upload`` finds
    ``file-upload``.
    """
    parts = (p.lower().replace("_", "-") for p in value.replace(",", " ").split())
    return list(dict.fromkeys(p for p in parts if p))


def load_attack_index() -> AttackIndex | None:
    """Read the cached ATT&CK index without blocking on a download.

    When the index is missing or stale, a background refresh is started so a
    later call gets current names; this call uses whatever is cached.

    Returns:
        The cached index (possibly stale), or None while it downloads.
    """
    index = AttackIndex.load()
    if index is None or index.is_stale:
        ensure_attack_index_background()
    return index


def library_error(error: LibraryError, extra: dict[str, object]) -> str:
    """Return the JSON error for an invalid project library."""
    logger.error(f"Threat library is invalid: {error}")
    return tool_error(
        "invalid_library",
        "The project's threat library files are invalid.",
        "Fix the files in .ai-security-crew/library/ or remove them to use the "
        "built-in library.",
        details=error.errors,
        **extra,
    )


def unknown_component_error(
    error: UnknownComponentError, extra: dict[str, object]
) -> str:
    """Return the JSON error for component ids that are not in the library."""
    return tool_error(
        "unknown_component",
        str(error),
        "Use ids from the component menu (call without components).",
        valid_components=error.valid,
        **extra,
    )
