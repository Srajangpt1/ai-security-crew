from dataclasses import dataclass


@dataclass(frozen=True)
class MainAppContext:
    """Settings loaded from environment variables at server startup."""

    read_only: bool = False
    enabled_tools: list[str] | None = None
