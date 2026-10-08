"""Helpers shared by the tools that read the threat library."""

import json
import logging

from mcp_security_review.library import LibraryError, UnknownComponentError

logger = logging.getLogger("mcp-security-review.servers.library")


def split_ids(value: str) -> list[str]:
    """Split a comma- or space-separated list of ids, keeping order.

    Ids are lowercased and underscores become hyphens, so ``File_Upload`` finds
    ``file-upload``.
    """
    parts = (p.lower().replace("_", "-") for p in value.replace(",", " ").split())
    return list(dict.fromkeys(p for p in parts if p))


def library_error(error: LibraryError, extra: dict[str, object]) -> str:
    """Return the JSON error for an invalid project library."""
    logger.error(f"Threat library is invalid: {error}")
    return json.dumps(
        {
            "success": False,
            "error": "The project's threat library files are invalid.",
            "details": error.errors,
            "hint": (
                "Fix the files in .ai-security-crew/library/ or remove them "
                "to use the built-in library."
            ),
            **extra,
        },
        indent=2,
        ensure_ascii=False,
    )


def unknown_component_error(
    error: UnknownComponentError, extra: dict[str, object]
) -> str:
    """Return the JSON error for component ids that are not in the library."""
    return json.dumps(
        {
            "success": False,
            "error": str(error),
            "valid_components": error.valid,
            "hint": "Use ids from the component menu (call without components).",
            **extra,
        },
        indent=2,
        ensure_ascii=False,
    )
