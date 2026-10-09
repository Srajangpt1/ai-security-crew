"""Tests for the sca_scan_dependencies tool."""

import json
from typing import Any
from unittest.mock import patch

import pytest
from fastmcp import Client

from mcp_security_review.providers.sca.osv import (
    OSVScanner,
    ScanResult,
    Vulnerability,
    VulnerableFunction,
)
from mcp_security_review.servers.main import main_mcp

PKGS = json.dumps([{"name": "pyjwt", "version": "2.4.0", "ecosystem": "pypi"}])


async def scan(results: list[ScanResult], **args: Any) -> dict[str, Any]:
    async def fake(self: OSVScanner, packages: list[dict]) -> list[ScanResult]:
        return results

    with patch.object(OSVScanner, "scan_packages", fake):
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
@pytest.mark.parametrize("tool", ["sca_scan_dependencies", "sca_verify_packages"])
async def test_bad_json_returns_shared_error_with_example(tool: str) -> None:
    data = await call_tool(tool, packages_json="not json")
    assert data["success"] is False
    assert data["error"]["code"] == "invalid_json"
    assert '"ecosystem": "pypi"' in data["error"]["hint"]


@pytest.mark.anyio
@pytest.mark.parametrize("tool", ["sca_scan_dependencies", "sca_verify_packages"])
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
