"""Jev client: request shape, retries and failure handling."""

import json
from typing import Any

import httpx
import pytest

from mcp_security_review.guard.jev import JevClient, JevError

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
