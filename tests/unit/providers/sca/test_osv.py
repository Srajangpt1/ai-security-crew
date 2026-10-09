"""Tests for OSV vulnerability scanner and reachability analysis."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mcp_security_review.providers.sca.osv import (
    OSVScanner,
    ReachabilityResult,
    ReachabilityStatus,
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

    def test_to_dict_with_reachability(self) -> None:
        vf = VulnerableFunction(name="decode", module="jwt")
        vuln = Vulnerability(
            id="CVE-2023-1234",
            summary="Test",
            severity="high",
            vulnerable_functions=[vf],
            reachability=[
                ReachabilityResult(
                    status=ReachabilityStatus.REACHABLE,
                    function=vf,
                    evidence="Function referenced: jwt.decode(",
                )
            ],
        )
        result = vuln.to_dict()
        assert result["reachability_summary"] == ReachabilityStatus.REACHABLE
        assert len(result["reachability"]) == 1


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
    async def test_scan_with_reachability(
        self, scanner: OSVScanner, mock_osv_response_with_vulns: dict
    ) -> None:
        mock_resp = AsyncMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_osv_response_with_vulns
        mock_resp.raise_for_status = lambda: None

        code = """
import jwt
token = jwt.decode(encoded, key, algorithms=['HS256'])
"""

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await scanner.scan_package(
                "pyjwt", "2.4.0", "pypi", code_snippets=[code]
            )
            assert result.has_vulnerabilities
            vuln = result.vulnerabilities[0]
            assert len(vuln.reachability) == 1
            assert vuln.reachability[0].status == ReachabilityStatus.REACHABLE
            assert "decode" in (vuln.reachability[0].evidence or "")

    @pytest.mark.asyncio
    async def test_scan_not_reachable(
        self, scanner: OSVScanner, mock_osv_response_with_vulns: dict
    ) -> None:
        mock_resp = AsyncMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_osv_response_with_vulns
        mock_resp.raise_for_status = lambda: None

        code = """
import jwt
token = jwt.encode(payload, key, algorithm='HS256')
"""

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await scanner.scan_package(
                "pyjwt", "2.4.0", "pypi", code_snippets=[code]
            )
            vuln = result.vulnerabilities[0]
            assert len(vuln.reachability) == 1
            # decode is not called, only encode
            assert vuln.reachability[0].status == ReachabilityStatus.NOT_REACHABLE

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


class TestReachabilityAnalysis:
    """Test the reachability checking logic."""

    @pytest.fixture
    def scanner(self) -> OSVScanner:
        return OSVScanner()

    def _make_vuln(
        self, functions: list[VulnerableFunction] | None = None
    ) -> Vulnerability:
        return Vulnerability(
            id="TEST-001",
            summary="Test vulnerability in decode function",
            severity="high",
            vulnerable_functions=functions or [],
        )

    def test_no_code_provided(self, scanner: OSVScanner) -> None:
        vuln = self._make_vuln()
        results = scanner._determine_reachability(
            vuln, "jwt", "PyPI", "", has_code=False
        )
        assert len(results) == 1
        assert results[0].status == ReachabilityStatus.NO_CODE_PROVIDED

    def test_package_not_imported(self, scanner: OSVScanner) -> None:
        code = "import requests\nresp = requests.get('https://example.com')"
        vuln = self._make_vuln()
        results = scanner._determine_reachability(
            vuln, "jwt", "PyPI", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.NOT_IMPORTED

    def test_python_function_reachable(self, scanner: OSVScanner) -> None:
        code = "import jwt\ntoken = jwt.decode(encoded, key, algorithms=['HS256'])"
        vf = VulnerableFunction(name="decode", module="jwt")
        vuln = self._make_vuln([vf])
        results = scanner._determine_reachability(
            vuln, "jwt", "PyPI", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.REACHABLE
        assert "decode" in (results[0].evidence or "")

    def test_python_from_import_reachable(self, scanner: OSVScanner) -> None:
        code = "from jwt import decode\nresult = decode(token, key)"
        vf = VulnerableFunction(name="decode", module="jwt")
        vuln = self._make_vuln([vf])
        results = scanner._determine_reachability(
            vuln, "jwt", "PyPI", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.REACHABLE

    def test_python_imported_but_not_called(self, scanner: OSVScanner) -> None:
        code = "import jwt\ntoken = jwt.encode(payload, key)"
        vf = VulnerableFunction(name="decode", module="jwt")
        vuln = self._make_vuln([vf])
        results = scanner._determine_reachability(
            vuln, "jwt", "PyPI", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.NOT_REACHABLE
        assert "not directly called" in (results[0].evidence or "")

    def test_js_reachable(self, scanner: OSVScanner) -> None:
        code = "const _ = require('lodash');\nconst result = _.template(input);"
        vf = VulnerableFunction(name="template", module="lodash")
        vuln = self._make_vuln([vf])
        results = scanner._determine_reachability(
            vuln, "lodash", "npm", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.REACHABLE

    def test_js_not_imported(self, scanner: OSVScanner) -> None:
        code = "const fs = require('fs');\nfs.readFileSync('file.txt');"
        vf = VulnerableFunction(name="template", module="lodash")
        vuln = self._make_vuln([vf])
        results = scanner._determine_reachability(
            vuln, "lodash", "npm", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.NOT_IMPORTED

    def test_ai_analysis_required_when_no_function_data(
        self, scanner: OSVScanner
    ) -> None:
        """When OSV has no function symbols and no keyword match, AI prompt is returned."""
        code = "from starlette.responses import JSONResponse\nreturn JSONResponse({'ok': True})"
        vuln = self._make_vuln()  # no vulnerable_functions
        vuln.summary = "Starlette DoS via some obscure internal mechanism"
        results = scanner._determine_reachability(
            vuln, "starlette", "PyPI", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.AI_ANALYSIS_REQUIRED
        assert results[0].reachability_prompt is not None
        assert "starlette" in (results[0].reachability_prompt or "").lower()

    def test_keyword_match_triggers_reachable(self, scanner: OSVScanner) -> None:
        """If vuln summary mentions 'FileResponse' and code uses it, flag reachable."""
        code = "from starlette.responses import FileResponse\nreturn FileResponse('file.txt')"
        vuln = self._make_vuln()
        vuln.summary = (
            "Starlette vulnerable to DoS via FileResponse Range header merging"
        )
        results = scanner._determine_reachability(
            vuln, "starlette", "PyPI", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.REACHABLE
        assert "FileResponse" in (results[0].evidence or "")


class TestDynamicImportDetection:
    """Test detection of dynamic import patterns."""

    @pytest.fixture
    def scanner(self) -> OSVScanner:
        return OSVScanner()

    def _make_vuln(self, functions: list[VulnerableFunction] | None = None) -> Vulnerability:
        return Vulnerability(
            id="TEST-DYN-001",
            summary="Test vulnerability",
            severity="high",
            vulnerable_functions=functions or [],
        )

    # ------ Python dynamic imports ------
    def test_importlib_import_module_detected(self, scanner: OSVScanner) -> None:
        code = "import importlib\nmod = importlib.import_module('pyjwt')"
        vuln = self._make_vuln()
        results = scanner._determine_reachability(
            vuln, "pyjwt", "PyPI", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.DYNAMIC_IMPORT
        assert "DYNAMIC" in (results[0].evidence or "")
        assert results[0].reachability_prompt is not None

    def test_dunder_import_detected(self, scanner: OSVScanner) -> None:
        code = "mod = __import__('requests')"
        vuln = self._make_vuln()
        results = scanner._determine_reachability(
            vuln, "requests", "PyPI", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.DYNAMIC_IMPORT

    def test_importlib_variable_flagged(self, scanner: OSVScanner) -> None:
        code = "import importlib\npkg_name = get_pkg()\nmod = importlib.import_module(pkg_name)"
        vuln = self._make_vuln()
        results = scanner._determine_reachability(
            vuln, "pyjwt", "PyPI", code, has_code=True
        )
        # Cannot confirm specific package but dynamic pattern detected
        assert results[0].status == ReachabilityStatus.DYNAMIC_IMPORT

    def test_exec_with_package_name_flagged(self, scanner: OSVScanner) -> None:
        code = "exec(\"import pyjwt; pyjwt.decode(token, key)\")"
        vuln = self._make_vuln()
        results = scanner._determine_reachability(
            vuln, "pyjwt", "PyPI", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.DYNAMIC_IMPORT

    def test_static_import_still_works_with_dynamic_present(
        self, scanner: OSVScanner
    ) -> None:
        """Static import takes priority over dynamic import detection."""
        code = "import jwt\ntoken = jwt.decode(t, k, algorithms=['HS256'])"
        vf = VulnerableFunction(name="decode", module="jwt")
        vuln = self._make_vuln([vf])
        results = scanner._determine_reachability(
            vuln, "pyjwt", "PyPI", code, has_code=True
        )
        # Static import found first — should be REACHABLE, not DYNAMIC_IMPORT
        assert results[0].status == ReachabilityStatus.REACHABLE

    # ------ JS dynamic imports ------
    def test_js_dynamic_import_detected(self, scanner: OSVScanner) -> None:
        code = "const mod = await import('lodash');"
        vuln = self._make_vuln()
        results = scanner._determine_reachability(
            vuln, "lodash", "npm", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.DYNAMIC_IMPORT

    def test_js_require_resolve_detected(self, scanner: OSVScanner) -> None:
        code = "const path = require.resolve('lodash');"
        vuln = self._make_vuln()
        results = scanner._determine_reachability(
            vuln, "lodash", "npm", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.DYNAMIC_IMPORT

    def test_js_require_variable_flagged(self, scanner: OSVScanner) -> None:
        code = "const pkgName = getPkg();\nconst mod = require(pkgName);"
        vuln = self._make_vuln()
        results = scanner._determine_reachability(
            vuln, "lodash", "npm", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.DYNAMIC_IMPORT

    def test_js_static_import_not_dynamic(self, scanner: OSVScanner) -> None:
        """Static require() with a literal string should NOT be flagged as dynamic."""
        code = "const _ = require('lodash');\n_.template(input);"
        vf = VulnerableFunction(name="template", module="lodash")
        vuln = self._make_vuln([vf])
        results = scanner._determine_reachability(
            vuln, "lodash", "npm", code, has_code=True
        )
        assert results[0].status == ReachabilityStatus.REACHABLE

    # ------ find_dynamic_import directly ------
    def test_find_dynamic_returns_none_when_absent(self, scanner: OSVScanner) -> None:
        code = "import requests\nresp = requests.get('https://example.com')"
        result = scanner._find_dynamic_import("requests", "PyPI", code, set())
        assert result is None

    def test_find_dynamic_import_module_with_string(self, scanner: OSVScanner) -> None:
        code = "importlib.import_module('yaml')"
        result = scanner._find_dynamic_import("yaml", "PyPI", code, set())
        assert result is not None
        assert "DYNAMIC" in result
