"""Package registry verification.

Checks if packages and their versions exist on PyPI, npm, etc.
Suggests corrections for hallucinated or misspelled packages.
"""

import logging
from dataclasses import dataclass, field

import httpx
from thefuzz import fuzz, process

from mcp_security_review.errors import error_body

logger = logging.getLogger(__name__)

PYPI_BASE_URL = "https://pypi.org/pypi"
NPM_BASE_URL = "https://registry.npmjs.org"

_ERROR_HINTS = {
    "unsupported_ecosystem": "Use 'pypi' or 'npm' as the ecosystem.",
    "registry_unavailable": (
        "The registry could not be reached, so this package is not confirmed "
        "missing. Retry, or tell the user it could not be verified."
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
    exists: bool
    version_exists: bool
    suggestion: str | None = None
    correct_name: str | None = None
    correct_version: str | None = None
    latest_version: str | None = None
    error: str | None = None
    error_code: str | None = None

    def is_valid(self) -> bool:
        return self.exists and self.version_exists

    def to_dict(self) -> dict:
        result: dict = {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "valid": self.is_valid(),
        }
        if self.error:
            result["error"] = error_body(
                self.error_code or "verification_failed",
                self.error,
                _ERROR_HINTS.get(
                    self.error_code or "", "Retry, or tell the user it could not run."
                ),
            )
        elif not self.is_valid():
            if not self.exists:
                result["issue"] = "package_not_found"
            elif not self.version_exists:
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
        ecosystem = ecosystem.lower().strip()
        if ecosystem in ("pypi", "pip", "python"):
            return await self._verify_pypi(name, version)
        elif ecosystem in ("npm", "node", "javascript", "js"):
            return await self._verify_npm(name, version)
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
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            for pkg in packages:
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                ecosystem = pkg.get("ecosystem", "pypi")
                result = await self._verify_with_client(
                    client, name, version, ecosystem
                )
                results.append(result)
        return results

    async def _verify_with_client(
        self,
        client: httpx.AsyncClient,
        name: str,
        version: str,
        ecosystem: str,
    ) -> PackageVerification:
        ecosystem = ecosystem.lower().strip()
        if ecosystem in ("pypi", "pip", "python"):
            return await self._verify_pypi_with_client(client, name, version)
        elif ecosystem in ("npm", "node", "javascript", "js"):
            return await self._verify_npm_with_client(client, name, version)
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
