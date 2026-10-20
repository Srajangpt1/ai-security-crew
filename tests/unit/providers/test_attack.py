"""Tests for the ATT&CK index: build from STIX, read from cache, refresh."""

import re
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest

from mcp_security_review.providers import attack
from mcp_security_review.providers.attack import (
    ATTACK_STIX_URL,
    AttackIndex,
    attack_summary,
    build_index,
    ensure_attack_index_background,
    refresh_attack_index,
)
from mcp_security_review.providers.intel import FetchError, IntelCache
from tests.conftest import ATTACK_FIXTURE

FIXTURE = ATTACK_FIXTURE


@pytest.fixture(scope="module")
def built() -> dict[str, Any]:
    """Build the index from the fixture bundle once for the module."""
    return build_index(FIXTURE)


@pytest.fixture
def index(built: dict[str, Any]) -> AttackIndex:
    return AttackIndex.from_dict(built)


@pytest.fixture
def no_thread_leak() -> Iterator[None]:
    """Wait for any refresh thread a test started, so tests stay isolated."""
    yield
    thread = attack._refresh_thread
    if thread is not None:
        thread.join(timeout=10)
        assert not thread.is_alive()


def test_build_index_from_fixture(built: dict[str, Any]) -> None:
    assert built["version"] == "20.0"
    assert isinstance(built["built_at"], str)
    t1190 = built["techniques"]["T1190"]
    assert t1190["id"] == "T1190"
    assert t1190["name"] == "Exploit Public-Facing Application"
    assert t1190["tactics"] == ["initial-access"]
    assert t1190["groups"]
    assert len(t1190["groups"]) <= 10
    assert all(set(g) == {"id", "name"} for g in t1190["groups"])
    assert all(re.fullmatch(r"G\d{4}", g["id"]) for g in t1190["groups"])
    assert all(re.fullmatch(r"S\d{4}", s["id"]) for s in t1190["software"])
    assert t1190["software"]
    assert t1190["mitigations"]
    assert all(m["id"].startswith("M") for m in t1190["mitigations"])
    assert t1190["detections"]
    assert all(isinstance(d, str) for d in t1190["detections"])
    assert t1190["url"] == "https://attack.mitre.org/techniques/T1190"
    assert t1190["revoked"] is False
    assert t1190["deprecated"] is False
    assert t1190["revoked_by"] is None
    assert t1190["platforms"]


def test_description_is_first_paragraph_without_citations(
    built: dict[str, Any],
) -> None:
    desc = built["techniques"]["T1190"]["description"]
    assert desc
    assert "\n\n" not in desc
    assert "(Citation:" not in desc
    assert len(desc) <= 600 + len("\n[... omitted ...]\n")


def test_subtechnique_and_lists_are_capped(built: dict[str, Any]) -> None:
    tech = built["techniques"]["T1078.004"]
    assert tech["name"] == "Cloud Accounts"
    for key in ("mitigations", "detections", "groups", "software"):
        assert len(tech[key]) <= 10
    names = [g["name"] for g in built["techniques"]["T1078"]["groups"]]
    assert names == sorted(names, key=str.lower)


def test_revoked_technique_flagged(index: AttackIndex) -> None:
    tech = index.technique("T1527")
    assert tech is not None
    assert tech["revoked"] is True
    assert tech["revoked_by"] == "T1550.001"
    cloud_logs = index.technique("T1562.008")
    assert cloud_logs is not None
    assert cloud_logs["revoked"] is True
    assert cloud_logs["revoked_by"] == "T1685.002"


def test_deprecated_technique_flagged(index: AttackIndex) -> None:
    tech = index.technique("T1064")
    assert tech is not None
    assert tech["deprecated"] is True


def test_technique_lookup_is_case_insensitive_and_unknown_is_none(
    index: AttackIndex,
) -> None:
    tech = index.technique("t1190")
    assert tech is not None and tech["id"] == "T1190"
    assert index.technique("T9999") is None
    assert index.technique("") is None


def test_search_by_name(index: AttackIndex) -> None:
    results = index.search("public-facing")
    assert results[0]["id"] == "T1190"
    valid = index.search("valid accounts")
    assert "T1078" in [r["id"] for r in valid]
    assert index.search("T1078.004")[0]["id"] == "T1078.004"
    assert len(index.search("a", limit=3)) <= 3
    assert index.search("") == []


def test_search_ranks_revoked_below_current(index: AttackIndex) -> None:
    ids = [r["id"] for r in index.search("application access token")]
    assert ids.index("T1550.001") < ids.index("T1527")


def test_from_dict_rejects_wrong_shape() -> None:
    with pytest.raises(ValueError):
        AttackIndex.from_dict({"version": 1, "techniques": {}})
    with pytest.raises(ValueError):
        AttackIndex.from_dict({"version": "20.0", "techniques": []})


def test_load_reads_stale_cache_and_ignores_corrupt(
    tmp_path: Path, built: dict[str, Any]
) -> None:
    cache = IntelCache(tmp_path)
    assert AttackIndex.load(cache) is None
    cache.put("attack-index", built)
    loaded = AttackIndex.load(cache)
    assert loaded is not None
    assert loaded.version == "20.0"
    assert loaded.fetched_at is not None
    assert loaded.is_stale is False
    assert loaded.technique("T1190") is not None
    (tmp_path / "attack-index.json").write_text("{half", encoding="utf-8")
    assert AttackIndex.load(cache) is None
    cache.put("attack-index", {"version": "x", "techniques": "nope"})
    assert AttackIndex.load(cache) is None


def test_summary_without_index_is_ids_only_and_pending() -> None:
    items, status = attack_summary(["T1190", "T1078"], None)
    assert items == [{"id": "T1190"}, {"id": "T1078"}]
    assert status == "pending: ATT&CK catalogue downloading; ids only"


def test_summary_with_index(index: AttackIndex) -> None:
    items, status = attack_summary(["T1190", "T1527", "T9999", "T1190"], index)
    assert status == "ok (ATT&CK 20.0)"
    assert items[0] == {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactics": ["initial-access"],
        "revoked": False,
        "revoked_by": None,
    }
    assert items[1]["revoked"] is True and items[1]["revoked_by"] == "T1550.001"
    assert items[2] == {"id": "T9999"}
    assert len(items) == 3


@pytest.mark.anyio
async def test_refresh_builds_and_caches_index(tmp_path: Path) -> None:
    body = FIXTURE.read_bytes()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, content=body)

    cache = IntelCache(tmp_path)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await refresh_attack_index(client, cache)
    assert seen == [ATTACK_STIX_URL]
    assert result["techniques"]["T1190"]["name"] == "Exploit Public-Facing Application"
    loaded = AttackIndex.load(cache)
    assert loaded is not None and loaded.version == "20.0"
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "attack-index.json"]
    assert leftovers == []


@pytest.mark.anyio
async def test_refresh_rejects_bad_bundle_and_cleans_up(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"type": "bundle", "objects": []}')

    cache = IntelCache(tmp_path)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(FetchError) as info:
            await refresh_attack_index(client, cache)
    assert info.value.code == "invalid_stix"
    assert AttackIndex.load(cache) is None
    assert [p.name for p in tmp_path.iterdir()] == []


def test_background_refresh_single_flight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_thread_leak: None
) -> None:
    started = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    async def fake_fetch_bytes(client: Any, url: str, **kw: Any) -> httpx.Response:
        calls.append(url)
        started.set()
        await anyio.to_thread.run_sync(release.wait, 10)
        return httpx.Response(200, content=FIXTURE.read_bytes())

    monkeypatch.setattr(attack, "fetch_bytes", fake_fetch_bytes)
    cache = IntelCache(tmp_path)
    assert ensure_attack_index_background(cache) is True
    assert started.wait(10)
    assert ensure_attack_index_background(cache) is False
    release.set()
    thread = attack._refresh_thread
    assert thread is not None and thread.daemon
    thread.join(timeout=30)
    assert not thread.is_alive()
    assert calls == [ATTACK_STIX_URL]
    loaded = AttackIndex.load(cache)
    assert loaded is not None
    # A fresh index is present now, so nothing more is started.
    assert ensure_attack_index_background(cache) is False


def test_refresh_failure_does_not_raise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_thread_leak: None
) -> None:
    errors: list[BaseException | None] = []
    monkeypatch.setattr(
        threading, "excepthook", lambda args: errors.append(args.exc_value)
    )

    async def failing(client: Any, url: str, **kw: Any) -> httpx.Response:
        raise FetchError("timeout")

    async def crashing(client: Any, url: str, **kw: Any) -> httpx.Response:
        raise RuntimeError("boom")

    cache = IntelCache(tmp_path)
    for fake in (failing, crashing):
        monkeypatch.setattr(attack, "fetch_bytes", fake)
        assert ensure_attack_index_background(cache) is True
        thread = attack._refresh_thread
        assert thread is not None
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert errors == []
    assert AttackIndex.load(cache) is None


def test_ensure_never_raises_on_bad_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken(IntelCache):
        def get(self, key: str, ttl: Any) -> Any:
            raise OSError("disk gone")

    assert ensure_attack_index_background(Broken(Path("/nonexistent"))) is False
