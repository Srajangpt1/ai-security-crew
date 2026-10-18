"""Client-independent events the guard works on."""

from dataclasses import dataclass, field
from typing import Any, Literal

Phase = Literal["pre", "post", "prompt"]

SHELL_TOOLS = frozenset({"Bash", "PowerShell"})
# Delete is Cursor's; deleting a hook file would switch the guard off.
FILE_WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit", "Delete"})
NETWORK_TOOLS = frozenset({"WebFetch", "WebSearch"})
# Tools that only read local state or hand work to another agent.
READ_ONLY_TOOLS = frozenset(
    {
        "Read",
        "Glob",
        "Grep",
        "LS",
        "NotebookRead",
        "TodoWrite",
        "ToolSearch",
        "Skill",
        "Task",
        "Agent",
    }
)
# Tools whose output is our own edit, not outside content.
NEVER_SCAN_TOOLS = FILE_WRITE_TOOLS | {"TodoWrite"}


@dataclass(frozen=True)
class Event:
    """One hook call, as seen by the guard."""

    phase: Phase
    session_id: str
    cwd: str = ""
    tool: str = ""
    tool_input: dict[str, Any] = field(default_factory=dict)
    tool_output: str = ""
    prompt: str = ""

    @property
    def kind(self) -> str:
        """Coarse action type: shell, file_write, network, mcp or other."""
        if self.tool in SHELL_TOOLS:
            return "shell"
        if self.tool in FILE_WRITE_TOOLS:
            return "file_write"
        if self.tool in NETWORK_TOOLS:
            return "network"
        if self.tool.startswith("mcp__"):
            return "mcp"
        return "other"
