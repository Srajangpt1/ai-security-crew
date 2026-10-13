"""Per-session memory: what the user said and what looked like an injection."""

import json
import os
import re
from pathlib import Path

from mcp_security_review.guard.clip import clip

MAX_PROMPTS = 5
MAX_FLAGGED = 5
MAX_TEXT = 1500


def guard_home() -> Path:
    """Folder for guard state; ASC_GUARD_HOME overrides the default."""
    override = os.environ.get("ASC_GUARD_HOME")
    return Path(override) if override else Path.home() / ".ai-security-crew" / "guard"


class SessionStore:
    """Small JSON file per session. Tool output never counts as user text."""

    def __init__(self, session_id: str, home: Path | None = None) -> None:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", session_id) or "unknown"
        self.path = (home or guard_home()) / "sessions" / f"{safe}.json"

    def _load(self) -> dict[str, list[str]]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"prompts": [], "flagged": []}
        return {k: [str(x) for x in data.get(k, [])] for k in ("prompts", "flagged")}

    def _save(self, data: dict[str, list[str]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(self.path)

    def add_prompt(self, text: str) -> None:
        """Remember a message the user typed."""
        data = self._load()
        data["prompts"] = [*data["prompts"], clip(text, MAX_TEXT, 0.6)][-MAX_PROMPTS:]
        self._save(data)

    def add_flagged(self, text: str) -> None:
        """Remember content that tried to instruct the agent."""
        data = self._load()
        data["flagged"] = [*data["flagged"], clip(text, MAX_TEXT)][-MAX_FLAGGED:]
        self._save(data)

    def prompts(self) -> list[str]:
        """The user's most recent messages, oldest first."""
        return self._load()["prompts"]

    def flagged(self) -> list[str]:
        """Content flagged earlier in this session."""
        return self._load()["flagged"]
