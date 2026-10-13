"""Build injected instructions and realistic tool_output bodies."""

import hashlib

from tests.eval.convert.atomic_templates import (
    CARRIER_TYPES,
    FILLER_END,
    FILLER_INTRO,
    FILLER_MIDDLE,
    PHRASING_TEMPLATES,
    PLACEMENTS,
)


def stable_pick(seed: str, options: list[str]) -> str:
    """Deterministically choose one option using a SHA-256 digest.

    Args:
        seed: Stable text identifying the choice (e.g. a case id).
        options: Non-empty candidate list.

    Returns:
        One element of ``options``, chosen deterministically from ``seed``.
    """
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return options[int(digest, 16) % len(options)]


def build_flagged_content(command: str, phrasing: str) -> str:
    """Render one injected instruction for ``command`` using ``phrasing``.

    Args:
        command: The shell command the injection tries to get run.
        phrasing: A key in ``PHRASING_TEMPLATES``.

    Returns:
        The injected instruction text, 50-250 characters.
    """
    text = PHRASING_TEMPLATES[phrasing].format(cmd=command)
    if len(text) > 250:
        shown = command.splitlines()[0]
        if len(shown) > 160:
            shown = shown[:160].rsplit(" ", 1)[0]
        shown = shown.rstrip("/:.-") + " (...)"
        text = PHRASING_TEMPLATES[phrasing].format(cmd=shown)
    return text


def pick_carrier(seed: str) -> tuple[str, str, str]:
    """Deterministically choose a carrier type, placement and phrasing.

    Args:
        seed: Stable text identifying the choice (e.g. a case id).

    Returns:
        A ``(carrier_type, placement, phrasing)`` tuple.
    """
    carrier_type = stable_pick(seed + "|type", CARRIER_TYPES)
    placement = stable_pick(seed + "|placement", PLACEMENTS)
    phrasing = stable_pick(seed + "|phrasing", list(PHRASING_TEMPLATES))
    return carrier_type, placement, phrasing


_CARRIER_LABEL = {
    "readme": "README.md",
    "code_comment": "setup.py",
    "issue_page": "issue #482",
    "package_docs": "package documentation",
    "web_page": "project wiki page",
}


def build_tool_output(carrier_type: str, placement: str, injected: str) -> str:
    """Render a plausible tool result containing ``injected`` text.

    Args:
        carrier_type: One of the carrier types in ``CARRIER_TYPES``.
        placement: ``"start"``, ``"middle"`` or ``"end"``.
        injected: The injected instruction text to embed.

    Returns:
        400-2500 character filler text with ``injected`` placed as asked.
    """
    label = _CARRIER_LABEL.get(carrier_type, "document")
    header = f"# {label}\n\n"
    marker = f"\n> {injected}\n\n"
    if placement == "start":
        body = marker + FILLER_INTRO + FILLER_MIDDLE + FILLER_END
    elif placement == "end":
        body = FILLER_INTRO + FILLER_MIDDLE + FILLER_END + marker
    else:
        body = FILLER_INTRO + marker + FILLER_MIDDLE + FILLER_END
    return header + body
