"""Tests for package registry verification."""

import json
import socket
from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, patch

import anyio
import httpx
import pytest

from mcp_security_review.providers.sca import registry as registry_module
from mcp_security_review.providers.sca.registry import (
    PackageRegistry,
    PackageVerification,
    parse_image,
    parse_pkt_lines,
    verify_action,
    verify_image,
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


# ---- GitHub Actions and container images ----

Handler = Callable[[httpx.Request], httpx.Response]

CHECKOUT_V4 = "11d5960a326750d5838078e36cf38b85af677262"
TAG_OBJECT = "a" * 40
MAIN_SHA = "b" * 40
V3_SHA = "c" * 40
DIGEST = "sha256:" + "d" * 64
HUB = "registry-1.docker.io"
PUBLIC_IP = "140.82.112.3"


def _pkt(line: str) -> bytes:
    data = line.encode()
    return f"{len(data) + 4:04x}".encode() + data


REFS_BODY = (
    _pkt("# service=git-upload-pack\n")
    + b"0000"
    + _pkt(f"{MAIN_SHA} HEAD\0multi_ack side-band-64k symref=HEAD:refs/heads/main\n")
    + _pkt(f"{MAIN_SHA} refs/heads/main\n")
    + _pkt(f"{V3_SHA} refs/tags/v3\n")
    + _pkt(f"{TAG_OBJECT} refs/tags/v4\n")
    + _pkt(f"{CHECKOUT_V4} refs/tags/v4^{{}}\n")
    + b"0000"
)


def _patch_dns(
    monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[str]]
) -> list[str]:
    """Patch anyio.getaddrinfo with a fixed name -> addresses map."""
    asked: list[str] = []

    async def fake_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any):
        asked.append(host)
        if host not in mapping:
            raise socket.gaierror(socket.EAI_NONAME, "not found")
        out = []
        for addr in mapping[host]:
            family = socket.AF_INET6 if ":" in addr else socket.AF_INET
            sockaddr = (addr, 443, 0, 0) if ":" in addr else (addr, 443)
            out.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return out

    monkeypatch.setattr(anyio, "getaddrinfo", fake_getaddrinfo)
    return asked


def _client(handler: Handler) -> tuple[httpx.AsyncClient, list[httpx.Request]]:
    calls: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request)

    return httpx.AsyncClient(transport=httpx.MockTransport(record)), calls


def _github(
    status: int = 200,
    body: bytes = REFS_BODY,
    *,
    owner_status: int = 200,
    owner_exc: Exception | None = None,
) -> Handler:
    """github.com: the refs endpoint, plus the owner page for 401/404 checks."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "github.com"
        if request.url.path.endswith("/info/refs"):
            assert request.url.params["service"] == "git-upload-pack"
            return httpx.Response(status, content=body if status == 200 else b"")
        assert request.method == "HEAD"
        assert request.url.path.count("/") == 1
        if owner_exc is not None:
            raise owner_exc
        return httpx.Response(owner_status)

    return handler


@pytest.fixture
def github_dns(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    return _patch_dns(monkeypatch, {"github.com": [PUBLIC_IP]})


def _bearer(realm: str, service: str, scope: str) -> str:
    return f'Bearer realm="{realm}",service="{service}",scope="{scope}"'


def _registry(
    *,
    host: str = HUB,
    realm: str = "https://auth.docker.io/token",
    token_status: int = 200,
    token_body: dict[str, Any] | None = None,
    authed_status: int | None = None,
    tags: dict[str, str] | None = None,
) -> Handler:
    """A registry that wants an anonymous bearer token, Docker Hub style."""
    known = {"3.12-slim": DIGEST} if tags is None else tags
    body = {"token": "tok123"} if token_body is None else token_body
    token = body.get("token") or body.get("access_token")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == host and request.url.path.startswith("/v2/"):
            assert request.method == "HEAD"
            repo, _, ref = request.url.path[4:].partition("/manifests/")
            if request.headers.get("authorization") != f"Bearer {token}":
                challenge = _bearer(
                    realm, "registry.docker.io", f"repository:{repo}:pull"
                )
                return httpx.Response(401, headers={"WWW-Authenticate": challenge})
            if authed_status is not None:
                return httpx.Response(authed_status)
            digest = DIGEST if ref == DIGEST else known.get(ref)
            if digest is None:
                return httpx.Response(404)
            return httpx.Response(200, headers={"Docker-Content-Digest": digest})
        if request.url.host == httpx.URL(realm).host:
            assert request.method == "GET"
            assert request.url.params["scope"].startswith("repository:")
            return httpx.Response(token_status, json=body)
        msg = f"unexpected request {request.url}"
        raise AssertionError(msg)

    return handler


@pytest.fixture
def hub_dns(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    return _patch_dns(
        monkeypatch,
        {
            HUB: [PUBLIC_IP],
            "auth.docker.io": [PUBLIC_IP],
            "registry.example.com": [PUBLIC_IP],
            "ghcr.io": [PUBLIC_IP],
            "internal.corp": ["10.0.0.2"],
            "metadata.example.com": ["169.254.169.254"],
            "v6.example.com": ["fd00::1"],
        },
    )


def test_pkt_line_parse_peels_annotated_tags() -> None:
    refs = parse_pkt_lines(REFS_BODY)
    assert refs["refs/tags/v4"] == CHECKOUT_V4
    assert refs["refs/tags/v3"] == V3_SHA
    assert refs["refs/heads/main"] == MAIN_SHA
    assert refs["HEAD"] == MAIN_SHA
    assert not any(name.endswith("^{}") for name in refs)


@pytest.mark.parametrize(
    "body", [b"", b"zzzz", b"00", b"ffff" + b"x" * 10, b"0008abcd", b"\xff\xfe00"]
)
def test_pkt_line_parse_tolerates_garbage(body: bytes) -> None:
    assert parse_pkt_lines(body) == {}


@pytest.mark.anyio
async def test_action_tag_suggests_sha(github_dns: list[str]) -> None:
    client, calls = _client(_github())
    async with client:
        result = await verify_action(client, "actions/checkout", "v4")
    assert result.is_valid()
    assert result.ecosystem == "github-actions"
    assert result.pinned is False
    assert result.suggested_fix == f"actions/checkout@{CHECKOUT_V4} # v4"
    data = result.to_dict()
    assert data["pinned"] is False
    assert data["suggested_fix"] == result.suggested_fix
    assert [str(r.url) for r in calls] == [
        "https://github.com/actions/checkout.git/info/refs?service=git-upload-pack"
    ]
    assert github_dns == ["github.com"]


@pytest.mark.anyio
async def test_action_with_path_uses_repo_and_keeps_path(
    github_dns: list[str],
) -> None:
    client, calls = _client(_github())
    async with client:
        result = await verify_action(client, "github/codeql-action/init", "v3")
    assert result.suggested_fix == f"github/codeql-action/init@{V3_SHA} # v3"
    assert calls[0].url.path == "/github/codeql-action.git/info/refs"


@pytest.mark.anyio
async def test_action_branch_ref_suggests_sha(github_dns: list[str]) -> None:
    client, _ = _client(_github())
    async with client:
        result = await verify_action(client, "actions/checkout", "main")
    assert result.pinned is False
    assert result.suggested_fix == f"actions/checkout@{MAIN_SHA} # main"


@pytest.mark.anyio
async def test_action_sha_pinned(github_dns: list[str]) -> None:
    client, _ = _client(_github())
    async with client:
        result = await verify_action(client, "actions/checkout", CHECKOUT_V4)
    assert result.is_valid()
    assert result.pinned is True
    assert result.status is None
    assert result.suggested_fix is None
    assert result.to_dict()["pinned"] is True


@pytest.mark.anyio
async def test_action_unknown_sha_is_unverified_not_invalid(
    github_dns: list[str],
) -> None:
    client, _ = _client(_github())
    async with client:
        result = await verify_action(client, "actions/checkout", "e" * 40)
    assert result.is_valid()
    assert result.status == "unverified_sha"
    assert result.version_exists is None
    assert result.pinned is True
    data = result.to_dict()
    assert data["status"] == "unverified_sha"
    assert "issue" not in data


@pytest.mark.anyio
@pytest.mark.parametrize("status", [404, 401])
async def test_action_missing_repo(github_dns: list[str], status: int) -> None:
    # GitHub answers 401 for private and missing repos alike; only a missing
    # owner proves the action does not exist.
    client, calls = _client(_github(status, owner_status=404))
    async with client:
        result = await verify_action(client, "no-such-owner-x/chekout", "v4")
    assert result.exists is False
    assert not result.is_valid()
    assert result.to_dict()["issue"] == "package_not_found"
    assert [(r.method, r.url.path) for r in calls] == [
        ("GET", "/no-such-owner-x/chekout.git/info/refs"),
        ("HEAD", "/no-such-owner-x"),
    ]


@pytest.mark.anyio
@pytest.mark.parametrize("status", [404, 401])
@pytest.mark.parametrize("owner_status", [200, 429, 500])
async def test_action_private_repo_cannot_verify(
    github_dns: list[str], status: int, owner_status: int
) -> None:
    client, _ = _client(_github(status, owner_status=owner_status))
    async with client:
        result = await verify_action(client, "actions/private-thing", "v4")
    assert result.status == "cannot_verify_anonymously"
    assert result.exists is None
    assert result.is_valid()
    data = result.to_dict()
    assert "issue" not in data
    assert data["note"]


@pytest.mark.anyio
async def test_action_owner_check_failing_cannot_verify(
    github_dns: list[str],
) -> None:
    handler = _github(401, owner_exc=httpx.ReadTimeout("slow"))
    client, _ = _client(handler)
    async with client:
        result = await verify_action(client, "actions/private-thing", "v4")
    assert result.status == "cannot_verify_anonymously"
    assert result.is_valid()


@pytest.mark.anyio
async def test_action_github_unresolvable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_dns(monkeypatch, {})
    client, calls = _client(_github())
    async with client:
        result = await verify_action(client, "actions/checkout", "v4")
    assert result.status == "registry_unresolvable"
    assert result.is_valid()
    assert calls == []


@pytest.mark.anyio
async def test_action_missing_ref(github_dns: list[str]) -> None:
    client, _ = _client(_github())
    async with client:
        result = await verify_action(client, "actions/checkout", "v99")
    assert result.exists is True
    assert result.version_exists is False
    assert result.to_dict()["issue"] == "version_not_found"


@pytest.mark.anyio
async def test_action_upstream_failure_is_error_not_invalid(
    github_dns: list[str],
) -> None:
    client, _ = _client(_github(503))
    async with client:
        result = await verify_action(client, "actions/checkout", "v4")
    assert result.error_code == "registry_unavailable"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("name", "ref"),
    [
        ("../x", "v4"),
        ("owner/..", "v4"),
        ("owner/repo/../../x", "v4"),
        ("docker://alpine", "3.8"),
        ("./local-action", "v1"),
        ("owner", "v1"),
        ("actions/checkout", "v4\r\nX: y"),
        ("actions/checkout", ""),
    ],
)
async def test_action_bad_name_no_request(
    github_dns: list[str], name: str, ref: str
) -> None:
    client, calls = _client(_github())
    async with client:
        result = await verify_action(client, name, ref)
    assert not result.is_valid()
    assert result.status == "invalid_name"
    data = result.to_dict()
    assert data["issue"] == "invalid_name"
    assert "local" in data["note"] and "docker://" in data["note"]
    assert calls == []
    assert github_dns == []


@pytest.mark.anyio
@pytest.mark.parametrize("verify", [verify_action, verify_image])
@pytest.mark.parametrize(("name", "ref"), [(5, "v1"), ("actions/checkout", 1)])
async def test_non_string_name_or_ref_is_invalid_name(
    github_dns: list[str], verify: Callable[..., Any], name: object, ref: object
) -> None:
    client, calls = _client(_github())
    async with client:
        result = await verify(client, name, ref)
    assert result.status == "invalid_name"
    assert result.to_dict()["issue"] == "invalid_name"
    assert json.dumps(result.to_dict())
    assert calls == []


@pytest.mark.anyio
async def test_registry_non_string_ecosystem_unsupported() -> None:
    result = await PackageRegistry().verify_package("x", "1", 5)  # type: ignore[arg-type]
    assert result.error_code == "unsupported_ecosystem"


@pytest.mark.parametrize(
    ("name", "registry", "repo"),
    [
        ("python", HUB, "library/python"),
        ("docker.io/python", HUB, "library/python"),
        ("index.docker.io/library/python", HUB, "library/python"),
        ("bitnami/redis", HUB, "bitnami/redis"),
        ("ghcr.io/owner/app", "ghcr.io", "owner/app"),
        ("GHCR.IO/owner/app", "ghcr.io", "owner/app"),
        ("localhost/app", "localhost", "app"),
        ("registry.example.com:5000/app", "registry.example.com:5000", "app"),
    ],
)
def test_parse_image(name: str, registry: str, repo: str) -> None:
    assert parse_image(name) == (registry, repo)


@pytest.mark.parametrize(
    "name", ["", "Python", "python:3.12", "a//b", "../etc", "x/../y", "a@sha256:00"]
)
def test_parse_image_rejects(name: str) -> None:
    assert parse_image(name) is None


@pytest.mark.anyio
async def test_image_tag_suggests_digest(hub_dns: list[str]) -> None:
    client, calls = _client(_registry())
    async with client:
        result = await verify_image(client, "python", "3.12-slim")
    assert result.is_valid()
    assert result.ecosystem == "container"
    assert result.pinned is False
    assert result.suggested_fix == f"python:3.12-slim@{DIGEST}"
    assert [(r.method, r.url.host) for r in calls] == [
        ("HEAD", HUB),
        ("GET", "auth.docker.io"),
        ("HEAD", HUB),
    ]
    assert calls[0].url.path == "/v2/library/python/manifests/3.12-slim"
    accept = calls[2].headers["accept"]
    assert "application/vnd.oci.image.index.v1+json" in accept
    assert "application/vnd.docker.distribution.manifest.v2+json" in accept
    token_url = calls[1].url
    assert token_url.params["service"] == "registry.docker.io"
    assert token_url.params["scope"] == "repository:library/python:pull"


@pytest.mark.anyio
async def test_image_access_token_field_and_ghcr(hub_dns: list[str]) -> None:
    handler = _registry(
        host="ghcr.io",
        realm="https://ghcr.io/token",
        token_body={"access_token": "ghcr-tok"},
        tags={"1.0": DIGEST},
    )
    client, _ = _client(handler)
    async with client:
        result = await verify_image(client, "ghcr.io/owner/app", "1.0")
    assert result.suggested_fix == f"ghcr.io/owner/app:1.0@{DIGEST}"


@pytest.mark.anyio
async def test_image_digest_pinned(hub_dns: list[str]) -> None:
    client, _ = _client(_registry())
    async with client:
        result = await verify_image(client, "python", DIGEST)
    assert result.is_valid()
    assert result.pinned is True
    assert result.suggested_fix is None


@pytest.mark.anyio
async def test_image_missing_tag_invalid(hub_dns: list[str]) -> None:
    client, _ = _client(_registry())
    async with client:
        result = await verify_image(client, "python", "no-such-tag")
    assert not result.is_valid()
    assert result.version_exists is False
    assert result.to_dict()["issue"] == "version_not_found"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("token_status", "authed_status"), [(200, 401), (200, 403), (401, None)]
)
async def test_image_private_registry_cannot_verify(
    hub_dns: list[str], token_status: int, authed_status: int | None
) -> None:
    handler = _registry(
        host="registry.example.com",
        realm="https://registry.example.com/token",
        token_status=token_status,
        authed_status=authed_status,
    )
    client, _ = _client(handler)
    async with client:
        result = await verify_image(client, "registry.example.com/team/app", "1.0")
    assert result.status == "cannot_verify_anonymously"
    assert result.is_valid()
    assert result.exists is None
    assert "issue" not in result.to_dict()


@pytest.mark.anyio
async def test_image_basic_auth_challenge_cannot_verify(hub_dns: list[str]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, headers={"WWW-Authenticate": 'Basic realm="x"'})

    client, calls = _client(handler)
    async with client:
        result = await verify_image(client, "registry.example.com/app", "1.0")
    assert result.status == "cannot_verify_anonymously"
    assert len(calls) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "name",
    [
        "internal.corp/app",
        "localhost/app",
        "metadata.example.com/app",
        "v6.example.com/a",
    ],
)
async def test_image_registry_resolving_private_refused(
    hub_dns: list[str], name: str
) -> None:
    client, calls = _client(_registry())
    async with client:
        result = await verify_image(client, name, "1.0")
    assert result.status == "unsafe_host"
    assert result.exists is None
    assert result.is_valid()
    assert "issue" not in result.to_dict()
    assert calls == []


@pytest.mark.anyio
async def test_image_custom_port_not_contacted(hub_dns: list[str]) -> None:
    client, calls = _client(_registry())
    async with client:
        result = await verify_image(client, "registry.example.com:5000/app", "1.0")
    assert result.status == "cannot_verify_anonymously"
    assert calls == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "realm",
    [
        "https://metadata.example.com/token",
        "https://169.254.169.254/latest/meta-data",
        "https://internal.corp/token",
        "http://auth.docker.io/token",
        "https://auth.docker.io:8443/token",
        "https://user:pw@auth.docker.io/token",
        "file:///etc/passwd",
    ],
)
async def test_token_realm_on_private_host_refused(
    hub_dns: list[str], realm: str
) -> None:
    client, calls = _client(_registry(realm=realm))
    async with client:
        result = await verify_image(client, "python", "3.12-slim")
    assert result.status == "unsafe_host"
    assert result.exists is None
    assert [(r.method, r.url.host) for r in calls] == [("HEAD", HUB)]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("name", "ref"),
    [("Python", "3.12"), ("python", "bad tag"), ("python", "sha256:abc"), ("", "1")],
)
async def test_image_bad_name_or_ref_no_request(
    hub_dns: list[str], name: str, ref: str
) -> None:
    client, calls = _client(_registry())
    async with client:
        result = await verify_image(client, name, ref)
    assert result.status == "invalid_name"
    assert not result.is_valid()
    assert result.to_dict()["issue"] == "invalid_name"
    assert calls == []
    assert hub_dns == []


@pytest.mark.anyio
async def test_image_registry_unresolvable(hub_dns: list[str]) -> None:
    client, calls = _client(_registry())
    async with client:
        result = await verify_image(client, "nxdomain.example.com/app", "1.0")
    assert result.status == "registry_unresolvable"
    assert result.exists is None
    assert result.is_valid()
    data = result.to_dict()
    assert "issue" not in data
    assert "resolve" in data["note"]
    assert calls == []


@pytest.mark.anyio
async def test_token_realm_unresolvable(hub_dns: list[str]) -> None:
    client, calls = _client(_registry(realm="https://nxdomain.example.com/token"))
    async with client:
        result = await verify_image(client, "python", "3.12-slim")
    assert result.status == "registry_unresolvable"
    assert [(r.method, r.url.host) for r in calls] == [("HEAD", HUB)]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("ecosystem", "canonical"),
    [
        ("github-actions", "github-actions"),
        ("actions", "github-actions"),
        ("GHA", "github-actions"),
        ("container", "container"),
        ("docker", "container"),
        ("oci", "container"),
        ("image", "container"),
    ],
)
async def test_registry_dispatches_new_ecosystems(
    hub_dns: list[str],
    monkeypatch: pytest.MonkeyPatch,
    ecosystem: str,
    canonical: str,
) -> None:
    _patch_dns(
        monkeypatch,
        {"github.com": [PUBLIC_IP], HUB: [PUBLIC_IP], "auth.docker.io": [PUBLIC_IP]},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "github.com":
            return _github()(request)
        return _registry()(request)

    def fake_client() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(registry_module, "new_client", fake_client)
    name, version = (
        ("actions/checkout", "v4")
        if canonical == "github-actions"
        else ("python", "3.12-slim")
    )
    reg = PackageRegistry()
    single = await reg.verify_package(name, version, ecosystem)
    batch = await reg.verify_packages(
        [{"name": name, "version": version, "ecosystem": ecosystem}]
    )
    for result in (single, batch[0]):
        assert result.ecosystem == canonical
        assert result.is_valid()
        assert result.pinned is False
        assert result.suggested_fix


def test_unsupported_ecosystem_hint_lists_new_ecosystems() -> None:
    hint = registry_module._ERROR_HINTS["unsupported_ecosystem"]
    assert "github-actions" in hint and "container" in hint


def test_token_body_is_json_dumpable() -> None:
    # The tool emits to_dict() through json.dumps; new fields must serialise.
    pv = PackageVerification(
        name="python",
        version="3.12-slim",
        ecosystem="container",
        exists=None,
        version_exists=None,
        status="unsafe_host",
    )
    assert json.loads(json.dumps(pv.to_dict()))["status"] == "unsafe_host"
