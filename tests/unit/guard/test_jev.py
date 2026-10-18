"""Jev client: request shape, retries and failure handling."""

import json
from typing import Any

import httpx
import pytest

from mcp_security_review.guard.jev import Answers, JevClient, JevError

OK = {
    "answers": {
        "a": {"noul": 0.9},
        "s": {"score": 2.0, "confidence": 0.8},
        "c": {"choice": "x"},
    }
}


def client(handler: Any, key: str = "k", timeout: float = 5) -> JevClient:
    return JevClient(
        url="https://jev.test/v1/systemone",
        api_key=key,
        timeout=timeout,
        transport=httpx.MockTransport(handler),
    )


def test_sends_state_questions_model_and_key() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=OK)

    answers = client(handler).ask("state", {"a": {"type": "noul"}})
    body = json.loads(seen[0].content)
    assert body["state"] == "state" and body["model"] == "jev-latest"
    assert body["questions"] == {"a": {"type": "noul"}}
    assert seen[0].headers["authorization"] == "Bearer k"
    assert answers.noul("a") == 0.9
    assert answers.score("s") == 2.0 and answers.confidence("s") == 0.8
    assert answers.choice("c") == "x"


def test_no_key_sends_no_authorization_header() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=OK)

    client(handler, key="").ask("s", {})
    assert "authorization" not in seen[0].headers


def test_retries_a_rate_limit_then_succeeds() -> None:
    codes = iter([429, 200])
    handler = lambda req: httpx.Response(next(codes), json=OK)  # noqa: E731
    assert client(handler).ask("s", {}).noul("a") == 0.9


def test_auth_failure_is_not_retried() -> None:
    calls: list[int] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(403, json={})

    with pytest.raises(JevError, match="403"):
        client(handler).ask("s", {})
    assert len(calls) == 1


def test_network_error_becomes_jev_error() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    with pytest.raises(JevError, match="network"):
        client(handler, timeout=1).ask("s", {})


@pytest.mark.parametrize("payload", [{}, {"answers": []}, "nope"])
def test_malformed_response(payload: Any) -> None:
    handler = lambda req: httpx.Response(200, json=payload)  # noqa: E731
    with pytest.raises(JevError, match="malformed"):
        client(handler).ask("s", {})


def test_missing_answer_is_an_error() -> None:
    handler = lambda req: httpx.Response(200, json=OK)  # noqa: E731
    with pytest.raises(JevError, match="missing"):
        client(handler).ask("s", {}).noul("nope")


def test_usage_and_model_are_kept() -> None:
    payload = {**OK, "model": "jev-1.13.0", "usage": {"input_tokens": 292}}
    handler = lambda req: httpx.Response(200, json=payload)  # noqa: E731
    answers = client(handler).ask("s", {})
    assert answers.input_tokens == 292 and answers.model == "jev-1.13.0"
    assert answers.raw["a"] == {"noul": 0.9}


def test_missing_usage_is_none() -> None:
    handler = lambda req: httpx.Response(200, json=OK)  # noqa: E731
    answers = client(handler).ask("s", {})
    assert answers.input_tokens is None and answers.model is None


@pytest.mark.parametrize(
    "answers",
    [
        {"q": {"score": "high", "noul": None, "choice": None}},
        {"q": {}},
        {"q": 5},
        {"q": ["x"]},
        {"q": {"score": float("nan"), "noul": float("inf")}},
    ],
)
def test_an_answer_of_the_wrong_shape_is_a_jev_error(answers: Any) -> None:
    a = Answers(answers)
    for read in (a.noul, a.score, a.choice):
        with pytest.raises(JevError):
            read("q")


def test_confidence_defaults_to_one_but_rejects_junk() -> None:
    assert Answers({"q": {}}).confidence("q") == 1.0
    for answers in ({"q": 5}, {"q": {"confidence": "sure"}}):
        with pytest.raises(JevError):
            Answers(answers).confidence("q")


@pytest.mark.parametrize("value", ["abc", "nan", "inf", "-5", "0", ""])
def test_a_bad_timeout_setting_falls_back_to_the_default(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("ASC_GUARD_TIMEOUT", value)
    assert JevClient().timeout == 10.0


def test_no_sleep_after_the_last_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("mcp_security_review.guard.jev.time.sleep", sleeps.append)
    handler = lambda req: httpx.Response(503)  # noqa: E731
    with pytest.raises(JevError):
        client(handler, timeout=10).ask("s", {})
    assert len(sleeps) == 2  # between the three attempts, not after the last
