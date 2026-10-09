"""Tests for the OSV vulnerability scanner and reachability checks."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mcp_security_review.providers.sca.osv import (
    OSVScanner,
    ScanResult,
    Vulnerability,
    VulnerableFunction,
)


class TestVulnerableFunction:
    def test_to_dict(self) -> None:
        vf = VulnerableFunction(name="decode", module="jwt")
        assert vf.to_dict() == {"name": "decode", "module": "jwt"}

    def test_to_dict_no_module(self) -> None:
        vf = VulnerableFunction(name="eval")
        assert vf.to_dict() == {"name": "eval"}


class TestVulnerability:
    def test_to_dict_basic(self) -> None:
        vuln = Vulnerability(
            id="CVE-2023-1234",
            summary="Test vulnerability",
            severity="high",
        )
        result = vuln.to_dict()
        assert result["id"] == "CVE-2023-1234"
        assert result["severity"] == "high"
        assert "vulnerable_functions" not in result

    def test_check_with_symbols(self) -> None:
        vuln = Vulnerability(
            id="CVE-2023-1234",
            summary="Test",
            severity="high",
            vulnerable_functions=[VulnerableFunction(name="decode", module="jwt")],
            fixed_versions=["2.6.0"],
        )
        result = vuln.to_dict()
        check = result["reachability_check"]
        assert check["symbols"] == [{"name": "decode", "module": "jwt"}]
        assert "2.6.0" in check["if_unsure"]
        assert result["fixed_versions"] == ["2.6.0"]

    def test_check_without_symbols(self) -> None:
        vuln = Vulnerability(id="CVE-1", summary="Test", severity="low")
        check = vuln.to_dict()["reachability_check"]
        assert check["symbols"] == "no_symbol_data"
        assert "No fixed version" in check["if_unsure"]


class TestScanResult:
    def test_clean_result(self) -> None:
        sr = ScanResult(name="requests", version="2.31.0", ecosystem="pypi")
        assert not sr.has_vulnerabilities
        assert sr.to_dict()["vulnerable"] is False

    def test_vulnerable_result(self) -> None:
        sr = ScanResult(
            name="pyjwt",
            version="2.4.0",
            ecosystem="pypi",
            vulnerabilities=[
                Vulnerability(
                    id="CVE-2023-1234",
                    summary="Test",
                    severity="high",
                )
            ],
        )
        assert sr.has_vulnerabilities
        result = sr.to_dict()
        assert result["vulnerable"] is True
        assert result["vulnerability_count"] == 1


class TestOSVScanner:
    @pytest.fixture
    def scanner(self) -> OSVScanner:
        return OSVScanner(timeout=5.0)

    @pytest.fixture
    def mock_osv_response_with_vulns(self) -> dict:
        return {
            "vulns": [
                {
                    "id": "GHSA-test-1234",
                    "summary": "JWT decode vulnerability",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.6.0"},
                                    ]
                                }
                            ],
                            "ecosystem_specific": {
                                "imports": [
                                    {
                                        "path": "jwt",
                                        "symbols": ["decode"],
                                    }
                                ]
                            },
                        }
                    ],
                    "references": [{"url": "https://github.com/test/advisory"}],
                }
            ]
        }

    @pytest.fixture
    def mock_osv_response_clean(self) -> dict:
        return {"vulns": []}

    @pytest.mark.asyncio
    async def test_scan_clean_package(
        self, scanner: OSVScanner, mock_osv_response_clean: dict
    ) -> None:
        mock_resp = AsyncMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_osv_response_clean
        mock_resp.raise_for_status = lambda: None

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await scanner.scan_package("requests", "2.31.0", "pypi")
            assert not result.has_vulnerabilities

    @pytest.mark.asyncio
    async def test_scan_vulnerable_package(
        self, scanner: OSVScanner, mock_osv_response_with_vulns: dict
    ) -> None:
        mock_resp = AsyncMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_osv_response_with_vulns
        mock_resp.raise_for_status = lambda: None

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await scanner.scan_package("pyjwt", "2.4.0", "pypi")
            assert result.has_vulnerabilities
            assert len(result.vulnerabilities) == 1
            vuln = result.vulnerabilities[0]
            assert vuln.id == "GHSA-test-1234"
            assert len(vuln.vulnerable_functions) == 1
            assert vuln.vulnerable_functions[0].name == "decode"
            assert vuln.vulnerable_functions[0].module == "jwt"

    @pytest.mark.asyncio
    async def test_scan_returns_reachability_check(
        self, scanner: OSVScanner, mock_osv_response_with_vulns: dict
    ) -> None:
        mock_resp = AsyncMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_osv_response_with_vulns
        mock_resp.raise_for_status = lambda: None

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await scanner.scan_package("pyjwt", "2.4.0", "pypi")
            vuln = result.vulnerabilities[0]
            assert vuln.fixed_versions == ["2.6.0"]
            check = result.to_dict()["vulnerabilities"][0]["reachability_check"]
            assert check["symbols"] == [{"name": "decode", "module": "jwt"}]

    @pytest.mark.asyncio
    async def test_scan_batch(
        self, scanner: OSVScanner, mock_osv_response_clean: dict
    ) -> None:
        batch_response = {
            "results": [
                {"vulns": []},
                {"vulns": []},
            ]
        }
        mock_resp = AsyncMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = batch_response
        mock_resp.raise_for_status = lambda: None

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            results = await scanner.scan_packages(
                [
                    {"name": "requests", "version": "2.31.0", "ecosystem": "pypi"},
                    {"name": "flask", "version": "3.0.0", "ecosystem": "pypi"},
                ]
            )
            assert len(results) == 2
            assert not any(r.has_vulnerabilities for r in results)

    def test_extract_severity(self, scanner: OSVScanner) -> None:
        # With database_specific severity
        vuln_data = {"database_specific": {"severity": "HIGH"}}
        assert scanner._extract_severity(vuln_data) == "high"

        # No severity info
        assert scanner._extract_severity({}) == "unknown"

    def test_extract_affected_versions(self, scanner: OSVScanner) -> None:
        vuln_data = {
            "affected": [
                {
                    "ranges": [
                        {
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.6.0"},
                            ]
                        }
                    ]
                }
            ]
        }
        versions = scanner._extract_affected_versions(vuln_data)
        assert ">=0,<2.6.0" in versions

    def test_extract_fixed_versions(self, scanner: OSVScanner) -> None:
        vuln_data = {
            "affected": [
                {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.6.0"}]}]},
                {"ranges": [{"events": [{"introduced": "3.0"}, {"fixed": "3.1.0"}]}]},
            ]
        }
        assert scanner._extract_fixed_versions(vuln_data) == ["2.6.0", "3.1.0"]

    def test_extract_vulnerable_functions_pypi(self, scanner: OSVScanner) -> None:
        vuln_data = {
            "affected": [
                {
                    "ecosystem_specific": {
                        "imports": [
                            {
                                "path": "jwt",
                                "symbols": ["decode", "encode"],
                            }
                        ]
                    }
                }
            ]
        }
        funcs = scanner._extract_vulnerable_functions(vuln_data)
        assert len(funcs) == 2
        assert funcs[0].name == "decode"
        assert funcs[0].module == "jwt"

    def test_extract_vulnerable_functions_npm(self, scanner: OSVScanner) -> None:
        vuln_data = {
            "affected": [{"ecosystem_specific": {"functions": ["lodash.template"]}}]
        }
        funcs = scanner._extract_vulnerable_functions(vuln_data)
        assert len(funcs) == 1
        assert funcs[0].name == "template"
        assert funcs[0].module == "lodash"
