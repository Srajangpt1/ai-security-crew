"""The guard's answer for one event."""

from dataclasses import dataclass
from typing import Literal

Action = Literal["allow", "ask", "deny"]
_EXIT_CODES: dict[str, int] = {"allow": 0, "ask": 1, "deny": 2}


@dataclass(frozen=True)
class Decision:
    """What to do with a tool call, why, and any note for the agent."""

    action: Action = "allow"
    reason: str = ""
    context: str = ""

    @property
    def exit_code(self) -> int:
        """Exit code used by `asc-guard check` (0 allow, 1 ask, 2 deny)."""
        return _EXIT_CODES[self.action]
