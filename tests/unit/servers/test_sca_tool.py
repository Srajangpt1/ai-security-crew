"""Tests for the sca_scan_dependencies tool."""

import json
from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import patch

import anyio
import pytest
from fastmcp import Client

from mcp_security_review.guard.clip import OMITTED
from mcp_security_review.providers.intel import ExploitContext, PackageAssessment
from mcp_security_review.providers.sca.osv import (
    OSVScanner,
    ScanResult,
    Vulnerability,
    VulnerableFunction,
)
from mcp_security_review.providers.sca.registry import (
    PackageRegistry,
    PackageVerification,
)
from mcp_security_review.servers.main import main_mcp

PKGS = json.dumps([{"name": "pyjwt", "version": "2.4.0", "ecosystem": "pypi"}])

BuildContexts = Callable[..., Awaitable[dict[str, ExploitContext]]]


async def _no_enrichment(
    vulns: list[Vulnerability], **kw: Any
) -> dict[str, ExploitContext]:
    """Default stand-in for `build_exploit_contexts`: no contexts, no network."""
    return {}


async def scan(
    results: list[ScanResult],
    *,
    build_contexts: BuildContexts | None = None,
    **args: Any,
) -> dict[str, Any]:
    async def fake(self: OSVScanner, packages: list[dict]) -> list[ScanResult]:
        return results

    with (
        patch.object(OSVScanner, "scan_packages", fake),
        patch(
            "mcp_security_review.servers.sca.build_exploit_contexts",
            build_contexts or _no_enrichment,
        ),
    ):
        async with Client(main_mcp) as client:
            result = await client.call_tool(
                "sca_scan_dependencies", {"packages_json": PKGS, **args}
            )
    items = result if isinstance(result, list) else result.content
    return json.loads(items[0].text)


@pytest.mark.anyio
async def test_vulnerability_carries_reachability_check() -> None:
    vuln = Vulnerability(
        id="GHSA-1",
        summary="s",
        severity="high",
        vulnerable_functions=[VulnerableFunction(name="decode", module="jwt")],
        fixed_versions=["2.6.0"],
    )
    data = await scan([ScanResult("pyjwt", "2.4.0", "pypi", vulnerabilities=[vuln])])
    assert data["status"] == "vulnerabilities_found"
    found = data["results"][0]["vulnerabilities"][0]
    assert found["reachability_check"]["symbols"][0]["name"] == "decode"
    assert "action_required" in data


@pytest.mark.anyio
async def test_failed_scan_is_not_reported_clean() -> None:
    data = await scan([ScanResult("pyjwt", "2.4.0", "pypi", error="OSV API error")])
    assert data["status"] == "scan_incomplete"
    assert data["errors"][0]["name"] == "pyjwt"


@pytest.mark.anyio
async def test_clean_scan() -> None:
    data = await scan([ScanResult("pyjwt", "2.6.0", "pypi")])
    assert data["status"] == "clean"


@pytest.mark.anyio
async def test_code_snippets_argument_is_gone() -> None:
    with pytest.raises(Exception):  # noqa: B017
        await scan([], code_snippets="x")


async def call_tool(tool: str, **args: Any) -> dict[str, Any]:
    async with Client(main_mcp) as client:
        result = await client.call_tool(tool, args)
    items = result if isinstance(result, list) else result.content
    return json.loads(items[0].text)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "tool", ["sca_scan_dependencies", "sca_verify_packages", "sca_assess_packages"]
)
async def test_bad_json_returns_shared_error_with_example(tool: str) -> None:
    data = await call_tool(tool, packages_json="not json")
    assert data["success"] is False
    assert data["error"]["code"] == "invalid_json"
    assert '"ecosystem": "pypi"' in data["error"]["hint"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "tool", ["sca_scan_dependencies", "sca_verify_packages", "sca_assess_packages"]
)
async def test_wrong_shape_returns_invalid_packages(tool: str) -> None:
    data = await call_tool(tool, packages_json='["requests"]')
    assert data["error"]["code"] == "invalid_packages"


@pytest.mark.anyio
async def test_scan_failure_has_code_and_hint() -> None:
    data = await scan(
        [
            ScanResult(
                "pyjwt",
                "2.4.0",
                "pypi",
                error="OSV API error: 403",
                error_code="osv_unavailable",
            )
        ]
    )
    error = data["errors"][0]["error"]
    assert error["code"] == "osv_unavailable"
    assert error["hint"]


@pytest.mark.anyio
async def test_scan_lists_upgrade_now_and_exploit_context() -> None:
    vuln = Vulnerability(id="CVE-2021-44228", summary="s", severity="critical")
    ctx = ExploitContext(
        cves=["CVE-2021-44228"],
        kev=True,
        kev_ransomware=True,
        kev_due_date="2021-12-24",
        epss=0.97,
        epss_percentile=0.99,
        priority="upgrade_now",
        sources={},
    )

    async def fake_build(
        vulns: list[Vulnerability], **kw: Any
    ) -> dict[str, ExploitContext]:
        return {v.id: ctx for v in vulns}

    data = await scan(
        [ScanResult("pyjwt", "2.4.0", "pypi", vulnerabilities=[vuln])],
        build_contexts=fake_build,
    )
    assert data["upgrade_now"] == ["CVE-2021-44228"]
    found = data["results"][0]["vulnerabilities"][0]
    assert found["exploit_context"]["priority"] == "upgrade_now"
    assert found["exploit_context"]["kev"] is True
    assert "upgrade_now" in data["action_required"]


@pytest.mark.anyio
async def test_scan_survives_enrichment_exception() -> None:
    vuln = Vulnerability(id="CVE-2021-44228", summary="s", severity="critical")

    async def fake_build(
        vulns: list[Vulnerability], **kw: Any
    ) -> dict[str, ExploitContext]:
        raise RuntimeError("boom")

    data = await scan(
        [ScanResult("pyjwt", "2.4.0", "pypi", vulnerabilities=[vuln])],
        build_contexts=fake_build,
    )
    assert data["status"] == "vulnerabilities_found"
    found = data["results"][0]["vulnerabilities"][0]
    assert found["exploit_context"]["sources"]["kev"].startswith("unavailable")
    assert found["exploit_context"]["sources"]["epss"].startswith("unavailable")
    assert data["upgrade_now"] == []


@pytest.mark.anyio
async def test_injected_summary_is_clipped() -> None:
    vuln = Vulnerability(id="GHSA-1", summary="A" * 10_000, severity="low")

    data = await scan([ScanResult("pyjwt", "2.4.0", "pypi", vulnerabilities=[vuln])])
    summary = data["results"][0]["vulnerabilities"][0]["summary"]
    assert len(summary) <= 500 + len(OMITTED)


async def lookup(
    lookups: dict[str, Vulnerability | None | Exception],
    *,
    build_contexts: BuildContexts | None = None,
    **args: Any,
) -> dict[str, Any]:
    async def fake(
        self: OSVScanner, vuln_id: str, *, client: Any = None
    ) -> Vulnerability | None:
        outcome = lookups[vuln_id]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    with (
        patch.object(OSVScanner, "lookup", fake),
        patch(
            "mcp_security_review.servers.sca.build_exploit_contexts",
            build_contexts or _no_enrichment,
        ),
    ):
        async with Client(main_mcp) as client:
            result = await client.call_tool("sca_lookup_vulnerability", args)
    items = result if isinstance(result, list) else result.content
    return json.loads(items[0].text)


@pytest.mark.anyio
async def test_lookup_found_with_exploit_context() -> None:
    vuln = Vulnerability(
        id="CVE-2021-44228",
        summary="s",
        severity="critical",
        affected_packages=[{"ecosystem": "Maven", "name": "log4j-core"}],
    )
    ctx = ExploitContext(
        cves=["CVE-2021-44228"],
        kev=True,
        kev_ransomware=True,
        kev_due_date="2021-12-24",
        epss=0.97,
        epss_percentile=0.99,
        priority="upgrade_now",
        sources={},
    )

    async def fake_build(
        vulns: list[Vulnerability], **kw: Any
    ) -> dict[str, ExploitContext]:
        return {v.id: ctx for v in vulns}

    data = await lookup(
        {"CVE-2021-44228": vuln},
        build_contexts=fake_build,
        vulnerability_ids="CVE-2021-44228",
    )
    assert data["success"] is True
    result = data["results"][0]
    assert result["requested_id"] == "CVE-2021-44228"
    assert result["id"] == "CVE-2021-44228"
    assert result["status"] == "found"
    assert "reachability_check" not in result
    assert result["affected_packages"] == [{"ecosystem": "Maven", "name": "log4j-core"}]
    assert result["exploit_context"]["priority"] == "upgrade_now"
    assert data["upgrade_now"] == ["CVE-2021-44228"]


@pytest.mark.anyio
async def test_lookup_found_reports_canonical_id_when_different() -> None:
    """OSV can resolve a requested id to a different canonical record

    (e.g. the requested id is an alias of the record OSV returns). Both
    the caller's original string and OSV's canonical id must be visible.
    """
    vuln = Vulnerability(id="GHSA-jfh8-c2jp-5v3q", summary="s", severity="critical")

    data = await lookup({"CVE-2021-44228": vuln}, vulnerability_ids="CVE-2021-44228")

    assert data["success"] is True
    result = data["results"][0]
    assert result["requested_id"] == "CVE-2021-44228"
    assert result["id"] == "GHSA-jfh8-c2jp-5v3q"
    assert result["status"] == "found"


@pytest.mark.anyio
async def test_lookup_not_found_is_not_failure() -> None:
    data = await lookup({"CVE-2099-0001": None}, vulnerability_ids="CVE-2099-0001")
    assert data["success"] is True
    assert data["results"] == [{"requested_id": "CVE-2099-0001", "status": "not_found"}]


@pytest.mark.anyio
async def test_lookup_mixed_valid_invalid() -> None:
    data = await lookup(
        {
            "CVE-2021-44228": Vulnerability(
                id="CVE-2021-44228", summary="s", severity="low"
            )
        },
        vulnerability_ids="CVE-2021-44228, not-an-id!!",
    )
    assert data["success"] is True
    statuses = {r["requested_id"]: r["status"] for r in data["results"]}
    assert statuses["CVE-2021-44228"] == "found"
    assert statuses["not-an-id!!"] == "invalid_id"


@pytest.mark.anyio
async def test_lookup_cap_20() -> None:
    ids = ", ".join(f"CVE-2024-{1000 + i}" for i in range(21))
    data = await lookup({}, vulnerability_ids=ids)
    assert data["success"] is False
    assert data["error"]["code"] == "too_many_ids"


@pytest.mark.anyio
async def test_lookup_osv_down_marks_lookup_failed() -> None:
    data = await lookup(
        {"CVE-2021-44228": RuntimeError("osv down")},
        vulnerability_ids="CVE-2021-44228",
    )
    assert data["success"] is True
    assert data["results"] == [
        {"requested_id": "CVE-2021-44228", "status": "lookup_failed"}
    ]


@pytest.mark.anyio
async def test_lookup_path_injection_id_rejected() -> None:
    called = False

    async def fake(
        self: OSVScanner, vuln_id: str, *, client: Any = None
    ) -> Vulnerability | None:
        nonlocal called
        called = True
        return None

    with patch.object(OSVScanner, "lookup", fake):
        async with Client(main_mcp) as client:
            result = await client.call_tool(
                "sca_lookup_vulnerability",
                {"vulnerability_ids": "../../v1/query"},
            )
    items = result if isinstance(result, list) else result.content
    data = json.loads(items[0].text)

    assert called is False
    assert data["results"] == [
        {"requested_id": "../../v1/query", "status": "invalid_id"}
    ]


@pytest.mark.anyio
async def test_lookup_shares_one_client_across_ids() -> None:
    """`OSVScanner.lookup` must be called with the same shared client for

    every id in the batch, not a fresh client per id.
    """
    seen_clients: list[Any] = []

    async def fake(
        self: OSVScanner, vuln_id: str, *, client: Any = None
    ) -> Vulnerability | None:
        seen_clients.append(client)
        return Vulnerability(id=vuln_id, summary="s", severity="low")

    with patch.object(OSVScanner, "lookup", fake):
        async with Client(main_mcp) as client:
            result = await client.call_tool(
                "sca_lookup_vulnerability",
                {"vulnerability_ids": "CVE-2021-44228, CVE-2021-44229"},
            )
    items = result if isinstance(result, list) else result.content
    data = json.loads(items[0].text)

    assert data["success"] is True
    assert len(seen_clients) == 2
    assert all(c is not None for c in seen_clients)
    assert seen_clients[0] is seen_clients[1]


@pytest.mark.anyio
async def test_lookup_preserves_request_order_under_concurrency() -> None:
    """Results must come back in request order even when ids resolve out

    of order, since lookups now run concurrently.
    """

    async def fake(
        self: OSVScanner, vuln_id: str, *, client: Any = None
    ) -> Vulnerability | None:
        if vuln_id == "CVE-2021-44228":
            await anyio.sleep(0.05)
        return Vulnerability(id=vuln_id, summary="s", severity="low")

    with patch.object(OSVScanner, "lookup", fake):
        async with Client(main_mcp) as client:
            result = await client.call_tool(
                "sca_lookup_vulnerability",
                {"vulnerability_ids": "CVE-2021-44228, CVE-2021-44229"},
            )
    items = result if isinstance(result, list) else result.content
    data = json.loads(items[0].text)

    assert [r["requested_id"] for r in data["results"]] == [
        "CVE-2021-44228",
        "CVE-2021-44229",
    ]


# ---- GitHub Actions and container images ----

_FIX = "actions/checkout@" + "1" * 40 + " # v4"


async def verify(results: list[PackageVerification]) -> dict[str, Any]:
    async def fake(self: PackageRegistry, packages: list[dict]) -> list:
        return results

    with patch.object(PackageRegistry, "verify_packages", fake):
        return await call_tool("sca_verify_packages", packages_json=PKGS)


def _pv(**kw: Any) -> PackageVerification:
    base: dict[str, Any] = {
        "name": "actions/checkout",
        "version": "v4",
        "ecosystem": "github-actions",
        "exists": True,
        "version_exists": True,
    }
    base.update(kw)
    return PackageVerification(**base)


@pytest.mark.anyio
async def test_tool_returns_unpinned_array() -> None:
    data = await verify(
        [
            _pv(pinned=False, suggested_fix=_FIX),
            _pv(version="1" * 40, pinned=True),
            _pv(name="requests", version="2.31.0", ecosystem="pypi"),
        ]
    )
    assert data["all_valid"] is True
    assert data["packages_checked"] == 3
    assert [u["suggested_fix"] for u in data["unpinned"]] == [_FIX]
    assert data["unpinned"][0]["pinned"] is False
    assert "action_required" in data


@pytest.mark.anyio
async def test_tool_unpinned_alongside_invalid() -> None:
    data = await verify(
        [
            _pv(pinned=False, suggested_fix=_FIX),
            _pv(name="actions/nope", exists=False, version_exists=False),
        ]
    )
    assert data["all_valid"] is False
    assert [p["name"] for p in data["invalid_packages"]] == ["actions/nope"]
    assert data["unpinned"][0]["suggested_fix"] == _FIX


@pytest.mark.anyio
async def test_tool_lists_unverified_without_failing() -> None:
    data = await verify(
        [
            _pv(
                name="internal.corp/app",
                ecosystem="container",
                exists=None,
                version_exists=None,
                status="unsafe_host",
            ),
            _pv(version="e" * 40, version_exists=None, status="unverified_sha"),
            _pv(exists=None, version_exists=None, status="cannot_verify_anonymously"),
            _pv(
                name="nxdomain.example.com/app",
                ecosystem="container",
                exists=None,
                version_exists=None,
                status="registry_unresolvable",
            ),
        ]
    )
    assert data["all_valid"] is True
    assert [u["status"] for u in data["unverified"]] == [
        "unsafe_host",
        "unverified_sha",
        "cannot_verify_anonymously",
        "registry_unresolvable",
    ]
    assert "unpinned" not in data


@pytest.mark.anyio
async def test_tool_descriptions_list_new_ecosystems() -> None:
    async with Client(main_mcp) as client:
        tools = {t.name: t for t in await client.list_tools()}
    for name in ("sca_verify_packages", "sca_scan_dependencies"):
        described = json.dumps(tools[name].inputSchema)
        for ecosystem in ("pypi", "npm", "github-actions"):
            assert ecosystem in described, (name, ecosystem)
    assert "container" in json.dumps(tools["sca_verify_packages"].inputSchema)


@pytest.mark.anyio
async def test_scan_accepts_github_actions_ecosystem() -> None:
    seen: list[str] = []

    async def fake_query(
        self: OSVScanner, client: Any, name: str, version: str, ecosystem: str
    ) -> list[Vulnerability]:
        seen.append(ecosystem)
        return []

    packages = json.dumps(
        [
            {"name": "actions/checkout", "version": "v4", "ecosystem": eco}
            for eco in ("github-actions", "actions", "gha")
        ]
    )

    with patch.object(OSVScanner, "_query_osv", fake_query):
        data = await call_tool("sca_scan_dependencies", packages_json=packages)
    assert data["status"] == "clean"
    assert seen == ["GitHub Actions"] * 3


@pytest.mark.anyio
@pytest.mark.parametrize(
    "tool", ["sca_scan_dependencies", "sca_verify_packages", "sca_assess_packages"]
)
@pytest.mark.parametrize(
    "package",
    [
        {"name": 5, "version": 1, "ecosystem": "container"},
        {"name": "python", "version": 3.12, "ecosystem": "container"},
        {"name": "python", "version": "3.12", "ecosystem": 5},
        {"name": ["x"], "version": "1"},
    ],
)
async def test_non_string_fields_rejected(tool: str, package: dict) -> None:
    async def no_lookup(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a lookup ran for a rejected package")

    with (
        patch.object(OSVScanner, "scan_packages", no_lookup),
        patch.object(PackageRegistry, "verify_packages", no_lookup),
    ):
        data = await call_tool(tool, packages_json=json.dumps([package]))
    assert data["success"] is False
    assert data["error"]["code"] == "invalid_packages"


# ---- sca_assess_packages ----


def _assessment(**kw: Any) -> PackageAssessment:
    base: dict[str, Any] = {
        "name": "requests",
        "version": "2.31.0",
        "ecosystem": "pypi",
        "exists": True,
        "deprecated": False,
        "deprecated_reason": None,
        "licenses": ["Apache-2.0"],
        "license_class": "permissive",
        "advisories": [],
        "provenance": True,
        "source_repo": "github.com/psf/requests",
        "scorecard": {"score": 8.2, "date": "2026-10-12", "weakest": []},
        "dependencies": {"direct": 1, "transitive": 1, "deprecated": []},
        "adoption_notes": [],
        "sources": {"deps_dev": "ok", "scorecard": "ok", "dependencies": "ok"},
    }
    base.update(kw)
    return PackageAssessment(**base)


@pytest.mark.anyio
async def test_assess_packages_returns_results_and_instructions() -> None:
    async def fake_assess(
        client: Any, name: str, version: str, ecosystem: str
    ) -> PackageAssessment:
        return _assessment(name=name, version=version, ecosystem=ecosystem)

    with patch("mcp_security_review.servers.sca.assess_package", fake_assess):
        data = await call_tool("sca_assess_packages", packages_json=PKGS)

    assert data["success"] is True
    assert data["packages_assessed"] == 1
    result = data["results"][0]
    assert result["license_class"] == "permissive"
    assert result["scorecard"]["score"] == 8.2
    assert "instructions" in data
    assert "not a verdict" in data["instructions"]


@pytest.mark.anyio
async def test_assess_packages_one_failure_does_not_fail_others() -> None:
    packages = json.dumps(
        [
            {"name": "good", "version": "1.0.0", "ecosystem": "pypi"},
            {"name": "bad", "version": "1.0.0", "ecosystem": "pypi"},
        ]
    )

    async def fake_assess(
        client: Any, name: str, version: str, ecosystem: str
    ) -> PackageAssessment:
        if name == "bad":
            raise RuntimeError("boom")
        return _assessment(name=name, version=version, ecosystem=ecosystem)

    with patch("mcp_security_review.servers.sca.assess_package", fake_assess):
        data = await call_tool("sca_assess_packages", packages_json=packages)

    assert data["success"] is True
    assert data["packages_assessed"] == 2
    names = [r["name"] for r in data["results"]]
    assert names == ["good", "bad"]
    bad_result = data["results"][1]
    assert bad_result["exists"] is False
    assert bad_result["sources"]["deps_dev"] == "unavailable: error"


@pytest.mark.anyio
async def test_tool_cap_25() -> None:
    packages = json.dumps(
        [
            {"name": f"pkg{i}", "version": "1.0.0", "ecosystem": "pypi"}
            for i in range(26)
        ]
    )

    async def no_lookup(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a lookup ran for a call over the cap")

    with patch("mcp_security_review.servers.sca.assess_package", no_lookup):
        data = await call_tool("sca_assess_packages", packages_json=packages)

    assert data["success"] is False
    assert data["error"]["code"] == "too_many_packages"


@pytest.mark.anyio
async def test_assess_packages_description_lists_ecosystems() -> None:
    async with Client(main_mcp) as client:
        tools = {t.name: t for t in await client.list_tools()}
    described = json.dumps(tools["sca_assess_packages"].inputSchema)
    for ecosystem in ("pypi", "npm", "github-actions"):
        assert ecosystem in described
