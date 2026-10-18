"""Client for TypeSafe's Jev decision model.

API reference: https://docs.typesafe.ai/api
"""

import math
import os
import time
from typing import Any

import httpx

DEFAULT_URL = "https://api.typesafe.ai/v1/systemone"
DEFAULT_TIMEOUT = 10.0
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
_ATTEMPTS = 3


class JevError(RuntimeError):
    """Jev could not be reached or returned something unusable."""


def _timeout_setting() -> float:
    """ASC_GUARD_TIMEOUT in seconds; anything unusable means the default."""
    try:
        value = float(os.environ.get("ASC_GUARD_TIMEOUT", DEFAULT_TIMEOUT))
    except ValueError:
        return DEFAULT_TIMEOUT
    return value if math.isfinite(value) and value > 0 else DEFAULT_TIMEOUT


def configured_key() -> str:
    """TYPESAFE_API_KEY, else the key saved in the Claude Code plugin's settings.

    Claude Code passes plugin settings to hooks as CLAUDE_PLUGIN_OPTION_<KEY>.
    """
    return os.environ.get("TYPESAFE_API_KEY") or os.environ.get(
        "CLAUDE_PLUGIN_OPTION_TYPESAFE_API_KEY", ""
    )


class Answers:
    """Typed access to the `answers` map of a Jev response."""

    def __init__(
        self,
        answers: dict[str, dict[str, Any]],
        input_tokens: int | None = None,
        model: str | None = None,
    ) -> None:
        self._answers = answers
        self.input_tokens = input_tokens
        self.model = model

    @property
    def raw(self) -> dict[str, dict[str, Any]]:
        """The answers exactly as the API returned them."""
        return self._answers

    def _field(self, name: str, field: str, default: Any = None) -> Any:
        answer = self._answers.get(name)
        if not isinstance(answer, dict):
            raise JevError(f"missing answer: {name}")
        if field not in answer and default is None:
            raise JevError(f"answer {name} has no {field}")
        return answer.get(field, default)

    def _number(self, name: str, field: str, default: float | None = None) -> float:
        # A wrong shape is the same as no answer: the guard steps aside.
        value = self._field(name, field, default)
        try:
            number = float(value)
        except (TypeError, ValueError) as e:
            raise JevError(f"answer {name}.{field} is not a number") from e
        if not math.isfinite(number):
            raise JevError(f"answer {name}.{field} is not a finite number")
        return number

    def noul(self, name: str) -> float:
        """Probability that a yes/no question is yes."""
        return self._number(name, "noul")

    def score(self, name: str) -> float:
        """Probability-weighted score of a score question."""
        return self._number(name, "score")

    def choice(self, name: str) -> str:
        """The option a choice question picked."""
        value = self._field(name, "choice")
        if not isinstance(value, str):
            raise JevError(f"answer {name}.choice is not text")
        return value

    def confidence(self, name: str) -> float:
        """Confidence reported for a score or choice answer (1.0 if absent)."""
        return self._number(name, "confidence", 1.0)


class JevClient:
    """Sends a state and typed questions to Jev and returns the answers."""

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.url = url or os.environ.get("ASC_GUARD_JEV_URL", DEFAULT_URL)
        self.api_key = api_key or configured_key()
        self.model = model or os.environ.get("ASC_GUARD_MODEL", "jev-latest")
        self.timeout = timeout or _timeout_setting()
        self._transport = transport

    def ask(self, state: Any, questions: dict[str, Any]) -> Answers:
        """Ask all questions about one state.

        Raises:
            JevError: On network failure, a bad status, or a malformed reply.
        """
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {"model": self.model, "state": state, "questions": questions}
        deadline = time.monotonic() + self.timeout
        last = "no attempt made"
        for attempt in range(_ATTEMPTS):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                with httpx.Client(timeout=remaining, transport=self._transport) as c:
                    resp = c.post(self.url, headers=headers, json=body)
            except httpx.HTTPError as e:
                last = f"network error: {e}"
            else:
                if resp.status_code == 200:
                    return self._parse(resp)
                last = f"HTTP {resp.status_code}"
                if resp.status_code not in _RETRY_STATUS:
                    break
            if attempt < _ATTEMPTS - 1:
                time.sleep(min(0.3 * 2**attempt, max(deadline - time.monotonic(), 0)))
        raise JevError(f"Jev unavailable ({last})")

    @staticmethod
    def _parse(resp: httpx.Response) -> Answers:
        try:
            body = resp.json()
            answers = body["answers"]
        except (ValueError, KeyError, TypeError) as e:
            raise JevError(f"malformed Jev response: {e}") from e
        if not isinstance(answers, dict):
            raise JevError("malformed Jev response: answers is not a map")
        usage = body.get("usage")
        tokens = usage.get("input_tokens") if isinstance(usage, dict) else None
        return Answers(answers, tokens, body.get("model"))
