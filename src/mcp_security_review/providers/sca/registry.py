"""Package registry verification.

Checks if packages and their versions exist on PyPI, npm, etc.
Suggests corrections for hallucinated or misspelled packages.
GitHub Actions refs and container images are also checked, and refs that
are not pinned to an immutable commit SHA or image digest are flagged.
"""

import logging
import re
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

import httpx
from thefuzz import fuzz, process

from mcp_security_review.errors import error_body
from mcp_security_review.providers.intel import (
    FetchError,
    UnresolvableHostError,
    UnsafeHostError,
    check_public_host,
    fetch_bytes,
    fetch_json,
    new_client,
)

logger = logging.getLogger(__name__)

PYPI_BASE_URL = "https://pypi.org/pypi"
NPM_BASE_URL = "https://registry.npmjs.org"

ACTIONS_ECOSYSTEM = "github-actions"
CONTAINER_ECOSYSTEM = "container"

_PYPI_ALIASES = frozenset({"pypi", "pip", "python"})
_NPM_ALIASES = frozenset({"npm", "node", "javascript", "js"})
_ACTIONS_ALIASES = frozenset({ACTIONS_ECOSYSTEM, "actions", "gha"})
_CONTAINER_ALIASES = frozenset({CONTAINER_ECOSYSTEM, "docker", "oci", "image"})

_ERROR_HINTS = {
    "unsupported_ecosystem": (
        "Use 'pypi', 'npm', 'github-actions', or 'container' as the ecosystem."
    ),
    "registry_unavailable": (
        "The registry could not be reached, so this package is not confirmed "
        "missing. Retry, or tell the user it could not be verified."
    ),
}

_STATUS_NOTES = {
    "invalid_name": (
        "Not a valid name or version for this ecosystem, so nothing was "
        "looked up. GitHub Actions: name 'owner/repo[/path]', version a tag, "
        "branch, or 40-character commit SHA; local actions ('./path') and "
        "'docker://' references are not registry packages and cannot be "
        "verified here. Containers: name '[registry/]repository' with no tag, "
        "version a tag or sha256 digest."
    ),
    "unverified_sha": (
        "This commit is not the tip of any branch or tag, so it could not be "
        "confirmed anonymously. It is not confirmed missing; check it is a "
        "commit of this repository and not of a fork."
    ),
    "cannot_verify_anonymously": (
        "The repository or registry needs credentials (it may be private, or "
        "use a non-standard port), so it could not be checked anonymously. "
        "It is not confirmed missing."
    ),
    "unsafe_host": (
        "The registry or its token service is not a public host, so it was "
        "not contacted. It is not confirmed missing; verify it yourself."
    ),
    "registry_unresolvable": (
        "The registry or its token service host name did not resolve in DNS, "
        "so it was not contacted. Check the host name for typos; it is not "
        "confirmed missing."
    ),
}

# Well-known packages for fuzzy matching fallback
_COMMON_PYPI_PACKAGES = [
    "requests",
    "flask",
    "django",
    "fastapi",
    "sqlalchemy",
    "pydantic",
    "pytest",
    "numpy",
    "pandas",
    "scipy",
    "boto3",
    "celery",
    "redis",
    "psycopg2",
    "cryptography",
    "paramiko",
    "pillow",
    "beautifulsoup4",
    "httpx",
    "aiohttp",
    "uvicorn",
    "gunicorn",
    "starlette",
    "click",
    "typer",
    "rich",
    "pyjwt",
    "python-dotenv",
    "jinja2",
    "marshmallow",
    "alembic",
    "black",
    "ruff",
    "mypy",
    "setuptools",
    "wheel",
    "pip",
    "poetry",
    "transformers",
    "torch",
    "tensorflow",
    "scikit-learn",
    "matplotlib",
    "seaborn",
    "lxml",
    "markdownify",
    "python-dateutil",
    "cachetools",
    "attrs",
    "dataclasses-json",
    "orjson",
    "ujson",
    "msgpack",
    "protobuf",
    "grpcio",
    "websockets",
    "trio",
    "anyio",
]

_COMMON_NPM_PACKAGES = [
    "express",
    "react",
    "next",
    "vue",
    "angular",
    "axios",
    "lodash",
    "typescript",
    "webpack",
    "vite",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "jsonwebtoken",
    "bcrypt",
    "helmet",
    "cors",
    "dotenv",
    "mongoose",
    "sequelize",
    "prisma",
    "zod",
    "joi",
    "winston",
    "pino",
    "chalk",
    "commander",
    "inquirer",
    "socket.io",
    "redis",
    "bull",
    "nodemailer",
    "sharp",
    "puppeteer",
    "cheerio",
    "date-fns",
    "moment",
    "uuid",
    "nanoid",
]


@dataclass
class VersionSuggestion:
    """Suggested version fix for a package."""

    latest: str
    available_versions: list[str] = field(default_factory=list)


@dataclass
class PackageVerification:
    """Result of verifying a single package."""

    name: str
    version: str
    ecosystem: str
    exists: bool | None
    """False when the package is definitely missing; None when unknown."""
    version_exists: bool | None
    """False when the version is definitely missing; None when unknown."""
    suggestion: str | None = None
    correct_name: str | None = None
    correct_version: str | None = None
    latest_version: str | None = None
    error: str | None = None
    error_code: str | None = None
    pinned: bool | None = None
    """For Actions and images: whether the ref is an immutable SHA or digest."""
    status: str | None = None
    """Why a check was inconclusive, or `invalid_name`; see `_STATUS_NOTES`."""
    suggested_fix: str | None = None
    """For an unpinned ref: the same reference pinned to its SHA or digest."""

    def is_valid(self) -> bool:
        """Say whether nothing is definitely missing.

        Returns:
            False only when the name or the version is known not to exist.
            Inconclusive checks (see `status`) count as valid.
        """
        return self.exists is not False and self.version_exists is not False

    def to_dict(self) -> dict:
        """Serialise for a tool response, omitting fields that are not set."""
        result: dict = {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "valid": self.is_valid(),
        }
        if self.status:
            result["status"] = self.status
            if self.status in _STATUS_NOTES:
                result["note"] = _STATUS_NOTES[self.status]
        if self.pinned is not None:
            result["pinned"] = self.pinned
        if self.suggested_fix:
            result["suggested_fix"] = self.suggested_fix
        if self.error:
            result["error"] = error_body(
                self.error_code or "verification_failed",
                self.error,
                _ERROR_HINTS.get(
                    self.error_code or "", "Retry, or tell the user it could not run."
                ),
            )
        elif not self.is_valid():
            if self.status == "invalid_name":
                result["issue"] = "invalid_name"
            elif self.exists is False:
                result["issue"] = "package_not_found"
            elif self.version_exists is False:
                result["issue"] = "version_not_found"
            if self.suggestion:
                result["suggestion"] = self.suggestion
            if self.correct_name:
                result["correct_name"] = self.correct_name
            if self.correct_version:
                result["correct_version"] = self.correct_version
            if self.latest_version:
                result["latest_version"] = self.latest_version
        return result


class PackageRegistry:
    """Verifies packages against PyPI and npm registries."""

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    async def verify_package(
        self, name: str, version: str, ecosystem: str
    ) -> PackageVerification:
        """Verify a single package exists with the given version."""
        ecosystem = str(ecosystem).lower().strip()
        if ecosystem in _PYPI_ALIASES:
            return await self._verify_pypi(name, version)
        elif ecosystem in _NPM_ALIASES:
            return await self._verify_npm(name, version)
        elif ecosystem in _ACTIONS_ALIASES | _CONTAINER_ALIASES:
            async with new_client() as client:
                return await self._verify_with_client(client, name, version, ecosystem)
        else:
            return PackageVerification(
                name=name,
                version=version,
                ecosystem=ecosystem,
                exists=False,
                version_exists=False,
                error=f"Unsupported ecosystem: {ecosystem}",
                error_code="unsupported_ecosystem",
            )

    async def verify_packages(self, packages: list[dict]) -> list[PackageVerification]:
        """Verify multiple packages. Each dict needs name, version, ecosystem."""
        results = []
        async with AsyncExitStack() as stack:
            client = await stack.enter_async_context(
                httpx.AsyncClient(timeout=self._timeout)
            )
            # Actions and images use the guarded intel client: their hosts can
            # come from the caller, so redirects and size caps must be checked.
            intel_client: httpx.AsyncClient | None = None
            for pkg in packages:
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                ecosystem = pkg.get("ecosystem", "pypi")
                use = client
                eco = str(ecosystem).lower().strip()
                if eco in _ACTIONS_ALIASES | _CONTAINER_ALIASES:
                    if intel_client is None:
                        intel_client = await stack.enter_async_context(new_client())
                    use = intel_client
                result = await self._verify_with_client(use, name, version, ecosystem)
                results.append(result)
        return results

    async def _verify_with_client(
        self,
        client: httpx.AsyncClient,
        name: str,
        version: str,
        ecosystem: str,
    ) -> PackageVerification:
        ecosystem = str(ecosystem).lower().strip()
        if ecosystem in _PYPI_ALIASES:
            return await self._verify_pypi_with_client(client, name, version)
        elif ecosystem in _NPM_ALIASES:
            return await self._verify_npm_with_client(client, name, version)
        elif ecosystem in _ACTIONS_ALIASES:
            return await verify_action(client, name, version)
        elif ecosystem in _CONTAINER_ALIASES:
            return await verify_image(client, name, version)
        else:
            return PackageVerification(
                name=name,
                version=version,
                ecosystem=ecosystem,
                exists=False,
                version_exists=False,
                error=f"Unsupported ecosystem: {ecosystem}",
                error_code="unsupported_ecosystem",
            )

    async def _verify_pypi(self, name: str, version: str) -> PackageVerification:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            return await self._verify_pypi_with_client(client, name, version)

    async def _verify_pypi_with_client(
        self,
        client: httpx.AsyncClient,
        name: str,
        version: str,
    ) -> PackageVerification:
        try:
            resp = await client.get(f"{PYPI_BASE_URL}/{name}/json")
            if resp.status_code == 404:
                suggestion = self._suggest_pypi_name(name)
                return PackageVerification(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    exists=False,
                    version_exists=False,
                    suggestion=(
                        f"Did you mean '{suggestion}'?" if suggestion else None
                    ),
                    correct_name=suggestion,
                )
            resp.raise_for_status()
            data = resp.json()
            releases = data.get("releases", {})
            latest = data.get("info", {}).get("version", "")

            # Strip leading 'v' if present
            clean_version = version.lstrip("v") if version.startswith("v") else version

            if clean_version in releases:
                return PackageVerification(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    exists=True,
                    version_exists=True,
                    latest_version=latest,
                )
            else:
                # Find closest version
                close_version = self._find_closest_version(
                    clean_version, list(releases.keys())
                )
                return PackageVerification(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    exists=True,
                    version_exists=False,
                    suggestion=(f"Version '{version}' not found. Latest: {latest}"),
                    correct_version=close_version or latest,
                    latest_version=latest,
                )
        except httpx.HTTPError as e:
            logger.error(f"PyPI lookup failed for {name}: {e}")
            return PackageVerification(
                name=name,
                version=version,
                ecosystem="pypi",
                exists=False,
                version_exists=False,
                error=f"Registry lookup failed: {e}",
                error_code="registry_unavailable",
            )

    async def _verify_npm(self, name: str, version: str) -> PackageVerification:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            return await self._verify_npm_with_client(client, name, version)

    async def _verify_npm_with_client(
        self,
        client: httpx.AsyncClient,
        name: str,
        version: str,
    ) -> PackageVerification:
        try:
            resp = await client.get(f"{NPM_BASE_URL}/{name}")
            if resp.status_code == 404:
                suggestion = self._suggest_npm_name(name)
                return PackageVerification(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    exists=False,
                    version_exists=False,
                    suggestion=(
                        f"Did you mean '{suggestion}'?" if suggestion else None
                    ),
                    correct_name=suggestion,
                )
            resp.raise_for_status()
            data = resp.json()
            versions = data.get("versions", {})
            dist_tags = data.get("dist-tags", {})
            latest = dist_tags.get("latest", "")

            clean_version = version.lstrip("v") if version.startswith("v") else version

            if clean_version in versions:
                return PackageVerification(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    exists=True,
                    version_exists=True,
                    latest_version=latest,
                )
            else:
                close_version = self._find_closest_version(
                    clean_version, list(versions.keys())
                )
                return PackageVerification(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    exists=True,
                    version_exists=False,
                    suggestion=(f"Version '{version}' not found. Latest: {latest}"),
                    correct_version=close_version or latest,
                    latest_version=latest,
                )
        except httpx.HTTPError as e:
            logger.error(f"npm lookup failed for {name}: {e}")
            return PackageVerification(
                name=name,
                version=version,
                ecosystem="npm",
                exists=False,
                version_exists=False,
                error=f"Registry lookup failed: {e}",
                error_code="registry_unavailable",
            )

    def _suggest_pypi_name(self, name: str) -> str | None:
        result = process.extractOne(
            name,
            _COMMON_PYPI_PACKAGES,
            scorer=fuzz.ratio,
            score_cutoff=60,
        )
        return result[0] if result else None

    def _suggest_npm_name(self, name: str) -> str | None:
        result = process.extractOne(
            name,
            _COMMON_NPM_PACKAGES,
            scorer=fuzz.ratio,
            score_cutoff=60,
        )
        return result[0] if result else None

    def _find_closest_version(self, target: str, available: list[str]) -> str | None:
        if not available:
            return None
        result = process.extractOne(
            target,
            available,
            scorer=fuzz.ratio,
            score_cutoff=70,
        )
        return result[0] if result else None


# ---- GitHub Actions and container images ----
#
# Both are checked over public, anonymous protocols: the git smart-HTTP ref
# advertisement on github.com, and the OCI distribution API with an anonymous
# bearer token. The registry host and the token realm come from the caller
# and from upstream headers, so both pass `check_public_host` before any
# request, and every request goes through `fetch_bytes(..., guard_host=True)`
# (HTTPS on port 443 only, no URL credentials, re-checked redirects, capped
# bodies).

ACTION_NAME_RE = r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}(/[A-Za-z0-9._/-]{1,200})?$"
REF_RE = r"^[A-Za-z0-9._/-]{1,200}$"
SHA_RE = r"^[0-9a-f]{40}$"
DIGEST_RE = r"^sha256:[0-9a-f]{64}$"
TAG_RE = r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$"
_IMAGE_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
IMAGE_RE = (
    r"^(?:(?P<registry>(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+(?::[0-9]{1,5})?"
    r"|[A-Za-z0-9-]+:[0-9]{1,5}|localhost)/)?"
    rf"(?P<repo>{_IMAGE_COMPONENT}(?:/{_IMAGE_COMPONENT})*)$"
)
"""`[registry/]repository`. The first part is a registry only when it has a
dot or a port, or is `localhost`; otherwise the name is a Docker Hub repo."""

_ACTION_NAME = re.compile(ACTION_NAME_RE)
_REF = re.compile(REF_RE)
_SHA = re.compile(SHA_RE)
_DIGEST = re.compile(DIGEST_RE)
_TAG = re.compile(TAG_RE)
_IMAGE = re.compile(IMAGE_RE)
_PKT_LEN = re.compile(rb"^[0-9a-fA-F]{4}$")
_CHALLENGE_PARAM = re.compile(r'([A-Za-z][A-Za-z0-9_-]*)\s*=\s*"([^"]*)"')
_TOKEN = re.compile(r"^[A-Za-z0-9._~+/=-]{1,16384}$")

GITHUB_URL = "https://github.com"
DOCKER_HUB_REGISTRY = "registry-1.docker.io"
_DOCKER_HUB_ALIASES = frozenset(
    {"docker.io", "index.docker.io", DOCKER_HUB_REGISTRY, "registry.hub.docker.com"}
)
_REFS_MAX_BYTES = 5 * 1024 * 1024
_MANIFEST_MAX_BYTES = 4 * 1024 * 1024  # the OCI spec's manifest size limit
_TOKEN_MAX_BYTES = 64 * 1024
_OWNER_PAGE_MAX_BYTES = 1024 * 1024
_MAX_IMAGE_NAME = 255
_MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


def _inconclusive(
    name: str, ref: str, ecosystem: str, status: str
) -> PackageVerification:
    """A result that is neither confirmed nor missing."""
    return PackageVerification(
        name=name,
        version=ref,
        ecosystem=ecosystem,
        exists=None,
        version_exists=None,
        status=status,
    )


def _invalid_name(name: object, ref: object, ecosystem: str) -> PackageVerification:
    """A result for a name or ref that is malformed, so never looked up."""
    return PackageVerification(
        name=str(name),
        version=str(ref),
        ecosystem=ecosystem,
        exists=False,
        version_exists=False,
        status="invalid_name",
    )


def _host_status(exc: FetchError) -> str:
    """Status for an `unsafe_host` refusal: unresolvable, or non-public."""
    if isinstance(exc.__cause__, UnresolvableHostError):
        return "registry_unresolvable"
    return "unsafe_host"


async def _github_owner_missing(client: httpx.AsyncClient, owner: str) -> bool:
    """Say whether github.com definitely has no user or org named `owner`.

    Smart HTTP answers 401 for a private repository and for a missing one
    alike, so only a 404 on the owner's page proves the action is missing.
    Any other answer, or any failure, is not proof.
    """
    try:
        await fetch_bytes(
            client,
            f"{GITHUB_URL}/{owner}",
            max_bytes=_OWNER_PAGE_MAX_BYTES,
            method="HEAD",
            guard_host=True,
        )
    except FetchError as exc:
        return exc.code == "http_404"
    return False


def _unavailable(
    name: str, ref: str, ecosystem: str, exc: FetchError
) -> PackageVerification:
    """A result for a lookup that failed for a reason other than missing."""
    return PackageVerification(
        name=name,
        version=ref,
        ecosystem=ecosystem,
        exists=False,
        version_exists=False,
        error=f"Registry lookup failed: {exc.code}",
        error_code="registry_unavailable",
    )


def parse_pkt_lines(body: bytes) -> dict[str, str]:
    """Parse a git smart-HTTP ref advertisement into ref names and SHAs.

    Args:
        body: The `info/refs?service=git-upload-pack` response body.

    Returns:
        Ref name to 40-character SHA. For an annotated tag, the peeled
        (`^{}`) commit SHA replaces the tag object's SHA, since that is the
        commit a workflow runs. Malformed input yields what parsed cleanly
        before it, never an exception.
    """
    refs: dict[str, str] = {}
    peeled: dict[str, str] = {}
    pos = 0
    while pos + 4 <= len(body):
        head = body[pos : pos + 4]
        if not _PKT_LEN.fullmatch(head):
            break
        size = int(head, 16)
        if size < 4:  # flush (0000), delimiter, or response-end packet
            pos += 4
            continue
        if pos + size > len(body):
            break
        payload = body[pos + 4 : pos + size]
        pos += size
        line = payload.rstrip(b"\n").split(b"\0", 1)[0]
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            continue
        sha, sep, ref = text.partition(" ")
        if not sep or not ref or not _SHA.fullmatch(sha):
            continue
        if ref.endswith("^{}"):
            peeled[ref[:-3]] = sha
        else:
            refs[ref] = sha
    for ref, sha in peeled.items():
        if ref in refs:
            refs[ref] = sha
    return refs


def _action_parts(name: str) -> tuple[str, str, str] | None:
    """Split `owner/repo[/path]` into owner, repo, and `/path` (or "")."""
    if not _ACTION_NAME.fullmatch(name):
        return None
    owner, repo, *rest = name.split("/")
    if any(part in ("", ".", "..") for part in (repo, *rest)):
        return None
    return owner, repo, "".join(f"/{part}" for part in rest)


async def verify_action(
    client: httpx.AsyncClient, name: object, ref: object
) -> PackageVerification:
    """Check a GitHub Action ref against the repository's advertised refs.

    Args:
        client: Client from `new_client`.
        name: `owner/repo` or `owner/repo/path`, as in `uses:`.
        ref: The part after `@`: a tag, branch, or 40-character commit SHA.

    Returns:
        A 404 or 401 from the repository gives `exists=False` only when the
        owner is missing too; otherwise the repository may be private, so
        the status is `cannot_verify_anonymously`. A missing tag or branch
        gives `version_exists=False`. A malformed name or ref (including
        local `./path` and `docker://` references) gives status
        `invalid_name` and no request. A SHA is `pinned`; one
        that is not a branch or tag tip has status `unverified_sha` and is
        not treated as missing. A tag or branch is valid but `pinned=False`,
        with `suggested_fix` pinning it to its commit SHA.
    """
    if not isinstance(name, str) or not isinstance(ref, str):
        return _invalid_name(name, ref, ACTIONS_ECOSYSTEM)
    parts = _action_parts(name)
    if parts is None or not _REF.fullmatch(ref):
        return _invalid_name(name, ref, ACTIONS_ECOSYSTEM)
    owner, repo, path = parts
    url = f"{GITHUB_URL}/{owner}/{repo}.git/info/refs?service=git-upload-pack"
    try:
        resp = await fetch_bytes(
            client, url, max_bytes=_REFS_MAX_BYTES, guard_host=True
        )
    except FetchError as exc:
        if exc.code in ("http_404", "http_401"):
            if not await _github_owner_missing(client, owner):
                return _inconclusive(
                    name, ref, ACTIONS_ECOSYSTEM, "cannot_verify_anonymously"
                )
            return PackageVerification(
                name=name,
                version=ref,
                ecosystem=ACTIONS_ECOSYSTEM,
                exists=False,
                version_exists=False,
                suggestion=f"No GitHub user or organization '{owner}'.",
            )
        if exc.code == "unsafe_host":
            return _inconclusive(name, ref, ACTIONS_ECOSYSTEM, _host_status(exc))
        logger.warning("GitHub refs lookup failed for %s: %s", name, exc.code)
        return _unavailable(name, ref, ACTIONS_ECOSYSTEM, exc)

    refs = parse_pkt_lines(resp.content)
    found = PackageVerification(
        name=name,
        version=ref,
        ecosystem=ACTIONS_ECOSYSTEM,
        exists=True,
        version_exists=True,
    )
    sha = ref.lower()
    if _SHA.fullmatch(sha):
        found.pinned = True
        if sha not in refs.values():
            found.version_exists = None
            found.status = "unverified_sha"
        return found

    candidates = (
        [ref] if ref.startswith("refs/") else [f"refs/tags/{ref}", f"refs/heads/{ref}"]
    )
    target = next((refs[c] for c in candidates if c in refs), None)
    if target is None:
        found.version_exists = False
        found.suggestion = f"No tag or branch '{ref}' in {owner}/{repo}."
        return found
    found.pinned = False
    found.suggested_fix = f"{owner}/{repo}{path}@{target} # {ref}"
    return found


def parse_image(name: str) -> tuple[str, str] | None:
    """Split an image name into registry host and repository path.

    Args:
        name: `[registry/]repository`, without tag or digest.

    Returns:
        `(registry, repository)`, with Docker Hub names mapped to
        `registry-1.docker.io` and single-part Hub names given `library/`;
        or None when the name is malformed.
    """
    if len(name) > _MAX_IMAGE_NAME:
        return None
    match = _IMAGE.fullmatch(name)
    if match is None:
        return None
    registry = (match.group("registry") or DOCKER_HUB_REGISTRY).lower()
    repo = match.group("repo")
    if registry in _DOCKER_HUB_ALIASES:
        registry = DOCKER_HUB_REGISTRY
        if "/" not in repo:
            repo = f"library/{repo}"
    return registry, repo


def _bearer_challenge(header: str) -> dict[str, str] | None:
    """Parse `Bearer realm="...",service="..."`; None for other schemes."""
    if len(header) > 4096:
        return None
    scheme, _, params = header.strip().partition(" ")
    if scheme.lower() != "bearer":
        return None
    return {key.lower(): value for key, value in _CHALLENGE_PARAM.findall(params)}


async def _anonymous_token(
    client: httpx.AsyncClient, challenge: str, repo: str
) -> str | None:
    """Get an anonymous pull token from the challenge's realm.

    Returns:
        The token, or None when the registry offers no anonymous token.

    Raises:
        FetchError: `unsafe_host` when the realm is not HTTPS on a public
            host (nothing is sent); other codes when the realm is
            unreachable.
    """
    params = _bearer_challenge(challenge)
    if not params or "realm" not in params:
        return None
    try:
        realm = httpx.URL(params["realm"])
    except httpx.InvalidURL as exc:
        raise FetchError("unsafe_host", "token realm is not a valid URL") from exc
    if realm.scheme != "https":
        raise FetchError("unsafe_host", "token realm is not https")
    try:
        await check_public_host(realm.host)
    except UnsafeHostError as exc:
        raise FetchError("unsafe_host", str(exc)) from exc
    query = {"scope": f"repository:{repo}:pull"}
    if params.get("service"):
        query = {"service": params["service"], **query}
    try:
        data: Any = await fetch_json(
            client,
            str(realm.copy_merge_params(query)),
            max_bytes=_TOKEN_MAX_BYTES,
            guard_host=True,
        )
    except FetchError as exc:
        if exc.code.startswith("http_4") or exc.code == "invalid_json":
            return None
        raise
    if not isinstance(data, dict):
        return None
    token = data.get("token") or data.get("access_token")
    if not isinstance(token, str) or not _TOKEN.fullmatch(token):
        return None
    return token


async def verify_image(
    client: httpx.AsyncClient, name: object, ref: object
) -> PackageVerification:
    """Check a container image tag or digest against its registry.

    Args:
        client: Client from `new_client`.
        name: `[registry/]repository`, for example `python` or
            `ghcr.io/owner/app`.
        ref: A tag, or a `sha256:` digest.

    Returns:
        A digest is `pinned`. A tag that exists is valid but `pinned=False`,
        with `suggested_fix` pinning it to the registry's digest. A missing
        manifest (404) gives `version_exists=False`. A registry that needs
        credentials or a non-standard port gives status
        `cannot_verify_anonymously`; a registry or token realm on a
        non-public host gives status `unsafe_host` (or
        `registry_unresolvable` when its name does not resolve) and is
        never contacted.
    """
    if not isinstance(name, str) or not isinstance(ref, str):
        return _invalid_name(name, ref, CONTAINER_ECOSYSTEM)
    parsed = parse_image(name)
    if parsed is None or not (_DIGEST.fullmatch(ref) or _TAG.fullmatch(ref)):
        return _invalid_name(name, ref, CONTAINER_ECOSYSTEM)
    registry, repo = parsed
    if ":" in registry:
        # Custom ports are refused by the guarded fetch; not checkable here.
        return _inconclusive(
            name, ref, CONTAINER_ECOSYSTEM, "cannot_verify_anonymously"
        )
    try:
        await check_public_host(registry)
    except UnresolvableHostError:
        return _inconclusive(name, ref, CONTAINER_ECOSYSTEM, "registry_unresolvable")
    except UnsafeHostError:
        return _inconclusive(name, ref, CONTAINER_ECOSYSTEM, "unsafe_host")

    url = f"https://{registry}/v2/{repo}/manifests/{ref}"
    headers = {"Accept": _MANIFEST_ACCEPT}
    try:
        try:
            resp = await fetch_bytes(
                client,
                url,
                max_bytes=_MANIFEST_MAX_BYTES,
                headers=headers,
                method="HEAD",
                guard_host=True,
            )
        except FetchError as exc:
            if exc.code != "http_401":
                raise
            challenge = exc.headers.get("www-authenticate", "")
            token = await _anonymous_token(client, challenge, repo)
            if token is None:
                return _inconclusive(
                    name, ref, CONTAINER_ECOSYSTEM, "cannot_verify_anonymously"
                )
            headers["Authorization"] = f"Bearer {token}"
            resp = await fetch_bytes(
                client,
                url,
                max_bytes=_MANIFEST_MAX_BYTES,
                headers=headers,
                method="HEAD",
                guard_host=True,
            )
    except FetchError as exc:
        if exc.code == "http_404":
            return PackageVerification(
                name=name,
                version=ref,
                ecosystem=CONTAINER_ECOSYSTEM,
                exists=None,
                version_exists=False,
                suggestion=f"No manifest '{ref}' for {registry}/{repo}.",
            )
        if exc.code in ("http_401", "http_403"):
            return _inconclusive(
                name, ref, CONTAINER_ECOSYSTEM, "cannot_verify_anonymously"
            )
        if exc.code == "unsafe_host":
            return _inconclusive(name, ref, CONTAINER_ECOSYSTEM, _host_status(exc))
        logger.warning("Registry lookup failed for %s: %s", name, exc.code)
        return _unavailable(name, ref, CONTAINER_ECOSYSTEM, exc)

    found = PackageVerification(
        name=name,
        version=ref,
        ecosystem=CONTAINER_ECOSYSTEM,
        exists=True,
        version_exists=True,
    )
    if _DIGEST.fullmatch(ref):
        found.pinned = True
        return found
    found.pinned = False
    digest = resp.headers.get("docker-content-digest", "").strip()
    if _DIGEST.fullmatch(digest):
        found.suggested_fix = f"{name}:{ref}@{digest}"
    else:
        found.suggestion = "The registry sent no digest; pin this image by digest."
    return found
