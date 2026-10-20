"""Tests for the OSV vulnerability scanner and reachability checks."""

from typing import Any
from unittest.mock import AsyncMock, patch

import anyio
import httpx
import pytest

from mcp_security_review.providers.intel import FetchError
from mcp_security_review.providers.sca.osv import (
    OSVScanner,
    ScanResult,
    Vulnerability,
    VulnerableFunction,
    level_for_score,
    score_severity,
)

V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"


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
        assert "confidence" in check["answer_with"]
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


class TestScoreSeverity:
    def test_v3_vector_only_scores_critical(self) -> None:
        s = score_severity({"severity": [{"type": "CVSS_V3", "score": V3}]})
        assert (s.level, s.score, s.source) == ("critical", 9.8, "cvss_v3")

    def test_v3_vector_with_database_fallback_still_scores_vector(self) -> None:
        s = score_severity(
            {
                "severity": [{"type": "CVSS_V3", "score": V3}],
                "database_specific": {"severity": "CRITICAL"},
            }
        )
        assert s.level == "critical" and s.source == "cvss_v3"

    def test_v4_vector_with_fallback_scores_vector(self) -> None:
        s = score_severity(
            {
                "severity": [{"type": "CVSS_V4", "score": V4}],
                "database_specific": {"severity": "CRITICAL"},
            }
        )
        assert s.source == "cvss_v4" and s.level == level_for_score(s.score)

    def test_v4_vector_only_is_not_unknown(self) -> None:
        s = score_severity({"severity": [{"type": "CVSS_V4", "score": V4}]})
        assert s.level != "unknown" and s.score is not None

    def test_v4_preferred_over_v3(self) -> None:
        s = score_severity(
            {
                "severity": [
                    {"type": "CVSS_V3", "score": V3},
                    {"type": "CVSS_V4", "score": V4},
                ]
            }
        )
        assert s.source == "cvss_v4"

    def test_malformed_vector_falls_back(self) -> None:
        s = score_severity(
            {
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:Q"}],
                "database_specific": {"severity": "HIGH"},
            }
        )
        assert (s.level, s.score, s.source) == ("high", None, "database_specific")

    def test_moderate_maps_to_medium(self) -> None:
        s = score_severity({"database_specific": {"severity": "MODERATE"}})
        assert s.level == "medium"

    def test_nothing_is_unknown(self) -> None:
        s = score_severity({})
        assert (s.level, s.score, s.vector, s.source) == ("unknown", None, None, "none")

    def test_non_list_severity_does_not_raise(self) -> None:
        s = score_severity({"severity": "x"})
        assert s.level == "unknown"


class TestLevelForScore:
    def test_bands(self) -> None:
        assert level_for_score(0.0) == "none"
        assert level_for_score(0.1) == "low"
        assert level_for_score(3.9) == "low"
        assert level_for_score(4.0) == "medium"
        assert level_for_score(6.9) == "medium"
        assert level_for_score(7.0) == "high"
        assert level_for_score(8.9) == "high"
        assert level_for_score(9.0) == "critical"
        assert level_for_score(10.0) == "critical"


class TestParseVulnAliases:
    def test_parse_vuln_keeps_aliases(self) -> None:
        v = OSVScanner().parse_vuln(
            {
                "id": "GHSA-x",
                "aliases": ["CVE-2024-1234", "PYSEC-1"],
                "severity": [{"type": "CVSS_V3", "score": V3}],
            }
        )
        assert v.aliases == ["CVE-2024-1234", "PYSEC-1"]
        assert v.to_dict()["aliases"] == ["CVE-2024-1234", "PYSEC-1"]
        assert v.cve_ids() == ["CVE-2024-1234"]
        assert v.severity == "critical"
        assert v.cvss_score == 9.8

    def test_cve_ids_includes_own_id_when_cve_shaped(self) -> None:
        v = OSVScanner().parse_vuln(
            {"id": "CVE-2024-1234", "aliases": ["GHSA-x", "CVE-2024-1234"]}
        )
        assert v.cve_ids() == ["CVE-2024-1234"]

    def test_cve_ids_excludes_malformed_cve_prefixed_alias(self) -> None:
        """A "CVE-"-prefixed alias that doesn't match the strict CVE shape
        (fewer than 4 digits after the year) is not a real CVE id and must
        not be returned by cve_ids().
        """
        v = OSVScanner().parse_vuln(
            {"id": "GHSA-x", "aliases": ["CVE-2024-1", "CVE-2024-1234"]}
        )
        assert v.cve_ids() == ["CVE-2024-1234"]

    def test_to_dict_omits_cvss_fields_when_unset(self) -> None:
        v = Vulnerability(id="CVE-1", summary="Test", severity="low", aliases=[])
        result = v.to_dict()
        assert "cvss_score" not in result
        assert "cvss_vector" not in result
        assert result["aliases"] == []


def _mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestOSVScannerLookup:
    @pytest.mark.asyncio
    async def test_lookup_found_parses_record(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/v1/vulns/GHSA-test-1234"
            return httpx.Response(
                200, json={"id": "GHSA-test-1234", "summary": "s", "aliases": []}
            )

        with patch(
            "mcp_security_review.providers.sca.osv.new_client",
            lambda timeout=15.0: _mock_client(handler),
        ):
            vuln = await OSVScanner().lookup("GHSA-test-1234")

        assert vuln is not None
        assert vuln.id == "GHSA-test-1234"

    @pytest.mark.asyncio
    async def test_lookup_not_found_returns_none(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        with patch(
            "mcp_security_review.providers.sca.osv.new_client",
            lambda timeout=15.0: _mock_client(handler),
        ):
            vuln = await OSVScanner().lookup("CVE-2024-99999")

        assert vuln is None

    @pytest.mark.asyncio
    async def test_lookup_other_failure_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        with patch(
            "mcp_security_review.providers.sca.osv.new_client",
            lambda timeout=15.0: _mock_client(handler),
        ):
            with pytest.raises(FetchError):
                await OSVScanner().lookup("GHSA-test-1234")

    @pytest.mark.asyncio
    async def test_lookup_url_encodes_id(self) -> None:
        """Defense in depth: the URL is built with `quote` regardless of
        whether the caller already validated the id's shape.
        """
        seen: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["path"] = request.url.raw_path.decode()
            return httpx.Response(200, json={"id": "x"})

        with patch(
            "mcp_security_review.providers.sca.osv.new_client",
            lambda timeout=15.0: _mock_client(handler),
        ):
            await OSVScanner().lookup("../../v1/query")

        assert seen["path"] == "/v1/vulns/..%2F..%2Fv1%2Fquery"

    @pytest.mark.asyncio
    async def test_lookup_populates_affected_packages_deduped_and_capped(
        self,
    ) -> None:
        affected = [
            {"package": {"name": "pyjwt", "ecosystem": "PyPI"}} for _ in range(25)
        ]
        affected[1] = {"package": {"name": "other", "ecosystem": "PyPI"}}

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"id": "GHSA-x", "affected": affected})

        with patch(
            "mcp_security_review.providers.sca.osv.new_client",
            lambda timeout=15.0: _mock_client(handler),
        ):
            vuln = await OSVScanner().lookup("GHSA-x")

        assert vuln is not None
        assert len(vuln.affected_packages) <= 20
        assert {"ecosystem": "PyPI", "name": "pyjwt"} in vuln.affected_packages

    @pytest.mark.asyncio
    async def test_lookup_reuses_given_client_and_does_not_close_it(self) -> None:
        """A caller looking up many ids shares one client across calls;

        `lookup` must use it as-is and never build or close its own.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"id": "GHSA-x"})

        given_client = _mock_client(handler)
        with patch(
            "mcp_security_review.providers.sca.osv.new_client",
            side_effect=AssertionError("new_client should not be called"),
        ):
            vuln = await OSVScanner().lookup("GHSA-x", client=given_client)

        assert vuln is not None
        assert given_client.is_closed is False
        await given_client.aclose()


@pytest.mark.anyio
async def test_scan_packages_concurrent_keeps_order_on_any_backend() -> None:
    # Runs on asyncio and trio: scan_packages must not be asyncio-only.
    delays = {"a": 0.03, "b": 0.0, "c": 0.01}

    async def fake_query(
        self: OSVScanner, client: Any, name: str, version: str, ecosystem: str
    ) -> list[Vulnerability]:
        await anyio.sleep(delays[name])
        return []

    packages = [{"name": n, "version": "1", "ecosystem": "pypi"} for n in "abc"]
    with patch.object(OSVScanner, "_query_osv", fake_query):
        results = await OSVScanner().scan_packages(packages)
    assert [r.name for r in results] == ["a", "b", "c"]
