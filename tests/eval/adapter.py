"""Judge benchmark cases with asc-guard, and two baselines."""

import os
import tempfile
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from mcp_security_review.guard import engine, jev, policy, session
from mcp_security_review.guard.events import Event
from tests.eval.cases import Case
from tests.eval.results import USD_PER_INPUT_TOKEN, Result

ACTION_SCORES = ("approval", "user_requested", "from_untrusted")


class Guard(Protocol):
    """Anything that can judge a case."""

    name: str

    def supports(self, case: Case) -> bool:
        """False for kinds of case this guard cannot judge."""
        ...

    def judge(self, case: Case, trial: int = 0) -> Result:
        """Judge one case without executing anything."""
        ...


class ConstantGuard:
    """Always answers the same thing: the floor every real guard must beat."""

    def __init__(self, action: str) -> None:
        self.action = action
        self.name = f"always-{action}"

    def supports(self, case: Case) -> bool:
        return True

    def judge(self, case: Case, trial: int = 0) -> Result:
        return Result(case_id=case.id, trial=trial, action=self.action, latency_ms=0.0)


class _Recorder:
    """Wraps a Jev client and keeps the last answers and any error."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.answers: jev.Answers | None = None
        self.error: str | None = None

    def ask(self, state: Any, questions: dict[str, Any]) -> jev.Answers:
        try:
            self.answers = self.inner.ask(state, questions)
        except jev.JevError as e:
            self.error = str(e)
            raise
        assert self.answers is not None
        return self.answers


class AscGuard:
    """The asc-guard engine, fed the same state it sees in a real session."""

    name = "asc-guard"

    def __init__(
        self,
        thresholds: policy.Thresholds | None = None,
        home: Path | None = None,
        client_factory: Callable[[], Any] = jev.JevClient,
    ) -> None:
        self.client_factory = client_factory
        self.thresholds = thresholds or policy.load_thresholds()
        self.home = home or Path(tempfile.mkdtemp(prefix="agb-"))
        os.environ["ASC_GUARD_HOME"] = str(self.home)

    def supports(self, case: Case) -> bool:
        return case.kind != "config_change"

    def judge(self, case: Case, trial: int = 0) -> Result:
        sid = f"{case.id}-{trial}-{uuid.uuid4().hex[:8]}"
        store = session.SessionStore(sid, self.home)
        for message in case.user_messages:
            store.add_prompt(message)
        for text in case.flagged_content:
            store.add_flagged(text)
        scan = case.kind == "result_scan"
        event = Event(
            "post" if scan else "pre",
            sid,
            "/repo",
            case.tool,
            case.tool_input,
            case.tool_output or "",
        )
        recorder = _Recorder(self.client_factory())
        start = time.perf_counter()
        decision = engine.handle(event, recorder, store, self.thresholds)
        wall = (time.perf_counter() - start) * 1000
        if recorder.error:
            return Result(case_id=case.id, trial=trial, error=recorder.error)
        action = ("deny" if decision.context else "allow") if scan else decision.action
        return self._result(case, trial, action, recorder.answers, wall)

    def _result(
        self,
        case: Case,
        trial: int,
        action: str,
        answers: jev.Answers | None,
        wall: float,
    ) -> Result:
        scores: dict[str, float] = {}
        confidence = tokens = model = None
        if answers is not None:
            if case.kind == "result_scan":
                scores = {"directed": answers.noul("directed")}
            else:
                scores = {n: answers.noul(n) for n in ACTION_SCORES}
                scores["risk"] = answers.score("risk")
                confidence = answers.confidence("risk")
            tokens, model = answers.input_tokens, answers.model
        cost = tokens * USD_PER_INPUT_TOKEN if tokens else None
        return Result(
            case_id=case.id,
            trial=trial,
            action=action,
            scores=scores,
            raw=answers.raw if answers else {},
            confidence=confidence,
            latency_ms=round(wall, 1),
            input_tokens=tokens,
            cost_usd=cost,
            model=model,
        )


def get_guard(name: str) -> Guard:
    """Look up a guard by name.

    Raises:
        ValueError: If the name is unknown.
    """
    if name == "asc-guard":
        return AscGuard()
    if name in ("always-allow", "always-ask"):
        return ConstantGuard(name.removeprefix("always-"))
    message = f"unknown guard {name!r}: asc-guard, always-allow or always-ask"
    raise ValueError(message)
