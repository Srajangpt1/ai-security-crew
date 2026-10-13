"""Shorten long text without losing either end."""

OMITTED = "\n[... omitted ...]\n"


def clip(text: str, limit: int, head_share: float = 0.4) -> str:
    """Keep the start and the end of text, dropping the middle.

    Injected instructions and the dangerous tail of a long command are both
    often at the end, so the end gets the larger share by default.

    Args:
        text: The text to shorten.
        limit: Characters to keep, not counting the omitted marker.
        head_share: Fraction of `limit` kept from the start.
    """
    if len(text) <= limit:
        return text
    head = int(limit * head_share)
    return f"{text[:head]}{OMITTED}{text[len(text) - (limit - head) :]}"
