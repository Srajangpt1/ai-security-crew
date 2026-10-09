"""Tests for package registry verification."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mcp_security_review.providers.sca.registry import (
    PackageRegistry,
    PackageVerification,
)


class TestPackageVerification:
    """Test PackageVerification dataclass."""

    def test_valid_package(self) -> None:
        pv = PackageVerification(
            name="requests",
            version="2.31.0",
            ecosystem="pypi",
            exists=True,
            version_exists=True,
        )
        assert pv.is_valid()
        result = pv.to_dict()
        assert result["valid"] is True
        assert "issue" not in result

    def test_invalid_package_not_found(self) -> None:
        pv = PackageVerification(
            name="nonexistent-pkg",
            version="1.0.0",
            ecosystem="pypi",
            exists=False,
            version_exists=False,
            suggestion="Did you mean 'requests'?",
            correct_name="requests",
        )
        assert not pv.is_valid()
        result = pv.to_dict()
        assert result["valid"] is False
        assert result["issue"] == "package_not_found"
        assert result["correct_name"] == "requests"

    def test_invalid_version(self) -> None:
        pv = PackageVerification(
            name="requests",
            version="99.99.99",
            ecosystem="pypi",
            exists=True,
            version_exists=False,
            correct_version="2.31.0",
            latest_version="2.31.0",
        )
        assert not pv.is_valid()
        result = pv.to_dict()
        assert result["issue"] == "version_not_found"
        assert result["correct_version"] == "2.31.0"


class TestPackageRegistry:
    """Test PackageRegistry with mocked HTTP responses."""

    @pytest.fixture
    def registry(self) -> PackageRegistry:
        return PackageRegistry(timeout=5.0)

    @pytest.fixture
    def mock_pypi_response(self) -> dict:
        return {
            "info": {"name": "requests", "version": "2.31.0"},
            "releases": {
                "2.28.0": [],
                "2.31.0": [],
                "2.30.0": [],
            },
        }

    @pytest.fixture
    def mock_npm_response(self) -> dict:
        return {
            "name": "express",
            "dist-tags": {"latest": "4.18.2"},
            "versions": {
                "4.17.1": {},
                "4.18.2": {},
            },
        }

    @pytest.mark.asyncio
    async def test_verify_pypi_valid(
        self, registry: PackageRegistry, mock_pypi_response: dict
    ) -> None:
        mock_resp = AsyncMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_pypi_response
        mock_resp.raise_for_status = lambda: None

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await registry.verify_package("requests", "2.31.0", "pypi")
            assert result.exists is True
            assert result.version_exists is True
            assert result.is_valid()

    @pytest.mark.asyncio
    async def test_verify_pypi_not_found(self, registry: PackageRegistry) -> None:
        mock_resp = AsyncMock(spec=httpx.Response)
        mock_resp.status_code = 404

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await registry.verify_package("reqeusts", "1.0.0", "pypi")
            assert result.exists is False
            # Should suggest "requests" via fuzzy match
            assert result.correct_name == "requests"

    @pytest.mark.asyncio
    async def test_verify_pypi_bad_version(
        self, registry: PackageRegistry, mock_pypi_response: dict
    ) -> None:
        mock_resp = AsyncMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_pypi_response
        mock_resp.raise_for_status = lambda: None

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await registry.verify_package("requests", "99.0.0", "pypi")
            assert result.exists is True
            assert result.version_exists is False
            assert result.latest_version == "2.31.0"

    @pytest.mark.asyncio
    async def test_verify_npm_valid(
        self, registry: PackageRegistry, mock_npm_response: dict
    ) -> None:
        mock_resp = AsyncMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_npm_response
        mock_resp.raise_for_status = lambda: None

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await registry.verify_package("express", "4.18.2", "npm")
            assert result.exists is True
            assert result.version_exists is True

    @pytest.mark.asyncio
    async def test_verify_unsupported_ecosystem(
        self, registry: PackageRegistry
    ) -> None:
        result = await registry.verify_package("some-pkg", "1.0.0", "unknown_eco")
        assert result.exists is False
        assert result.error is not None
        assert "Unsupported ecosystem" in result.error
        error = result.to_dict()["error"]
        assert error["code"] == "unsupported_ecosystem"
        assert "pypi" in error["hint"]
        assert "issue" not in result.to_dict()

    @pytest.mark.asyncio
    async def test_verify_packages_batch(
        self, registry: PackageRegistry, mock_pypi_response: dict
    ) -> None:
        mock_resp = AsyncMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_pypi_response
        mock_resp.raise_for_status = lambda: None

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            results = await registry.verify_packages(
                [
                    {"name": "requests", "version": "2.31.0", "ecosystem": "pypi"},
                    {"name": "requests", "version": "2.28.0", "ecosystem": "pypi"},
                ]
            )
            assert len(results) == 2
            assert all(r.is_valid() for r in results)

    def test_suggest_pypi_name(self, registry: PackageRegistry) -> None:
        assert registry._suggest_pypi_name("reqeusts") == "requests"
        assert registry._suggest_pypi_name("flaks") == "flask"
        # Very different name should return None
        assert registry._suggest_pypi_name("zzzzzzzzzzz") is None

    def test_suggest_npm_name(self, registry: PackageRegistry) -> None:
        assert registry._suggest_npm_name("exprss") == "express"
        assert registry._suggest_npm_name("ract") == "react"

    def test_find_closest_version(self, registry: PackageRegistry) -> None:
        versions = ["2.28.0", "2.30.0", "2.31.0"]
        assert registry._find_closest_version("2.31.1", versions) == "2.31.0"
        assert registry._find_closest_version("2.29.0", versions) is not None
