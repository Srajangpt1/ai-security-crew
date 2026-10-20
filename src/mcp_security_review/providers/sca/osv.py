"""OSV.dev vulnerability scanner.

Queries the OSV.dev API for known vulnerabilities. Each vulnerability
carries a reachability check (affected symbols plus a question) that the
calling agent answers by reading its own code; the server does not
decide reachability.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import anyio
import cvss
import httpx

from mcp_security_review.errors import error_body
from mcp_security_review.providers.intel import (
    FetchError,
    fetch_json,
    new_client,
    untrusted,
)

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1"
OSV_QUERY_URL = f"{OSV_API_URL}/query"

_LOOKUP_MAX_BYTES = 2 * 1024 * 1024
_MAX_AFFECTED_PACKAGES = 20

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

_SUMMARY_LIMIT = 500
"""OSV summaries are third-party feed text; clip them with `untrusted`."""

# --- CVSS severity scoring -------------------------------------------------
#
# OSV records a CVSS vector string (not a numeric score) under
# severity[].score. This section parses that vector with the `cvss`
# package to get a base score, preferring CVSS v4 over v3, and falls back
# to database_specific.severity only when no vector is present or the
# vector fails to parse.

_DATABASE_SEVERITY_LEVELS = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
}


@dataclass(frozen=True)
class SeverityInfo:
    """Resolved severity for a vulnerability record.

    Attributes:
        level: One of critical, high, medium, low, none, unknown.
        score: The CVSS base score, when derived from a CVSS vector.
        vector: The CVSS vector string that produced the score, if any.
        source: Where the severity came from: cvss_v4, cvss_v3,
            database_specific, or none.
    """

    level: str
    score: float | None
    vector: str | None
    source: str


def level_for_score(score: float) -> str:
    """Map a CVSS base score (v3 or v4) to a severity level.

    Args:
        score: A CVSS v3 or v4 base score in the 0.0-10.0 range. Both
            versions use the same severity bands.

    Returns:
        One of `none`, `low`, `medium`, `high`, `critical`.
    """
    if score <= 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def score_severity(vuln_data: dict[str, Any]) -> SeverityInfo:
    """Score an OSV vulnerability record's severity.

    Prefers a CVSS v4 vector, then CVSS v3, then
    `database_specific.severity`. Returns `level="unknown"` only when no
    usable severity information is present at all.

    Args:
        vuln_data: A raw OSV vulnerability record (the `dict` returned
            under `vulns[]` from the OSV API), as passed to
            `OSVScanner.parse_vuln`.

    Returns:
        The resolved `SeverityInfo` for this record.
    """
    severity_list = vuln_data.get("severity", [])
    if not isinstance(severity_list, list):
        severity_list = []

    v3_vector: str | None = None
    v4_vector: str | None = None
    for sev in severity_list:
        if not isinstance(sev, dict):
            continue
        sev_type = sev.get("type")
        score_str = sev.get("score")
        if not isinstance(score_str, str):
            continue
        if sev_type == "CVSS_V4":
            v4_vector = score_str
        elif sev_type == "CVSS_V3":
            v3_vector = score_str

    if v4_vector:
        try:
            base_score = float(cvss.CVSS4(v4_vector).base_score)
            return SeverityInfo(
                level=level_for_score(base_score),
                score=base_score,
                vector=v4_vector,
                source="cvss_v4",
            )
        except (cvss.CVSSError, ValueError, KeyError, TypeError):
            logger.debug("Unparseable CVSS v4 vector: %s", v4_vector)

    if v3_vector:
        try:
            base_score = float(cvss.CVSS3(v3_vector).base_score)
            return SeverityInfo(
                level=level_for_score(base_score),
                score=base_score,
                vector=v3_vector,
                source="cvss_v3",
            )
        except (cvss.CVSSError, ValueError, KeyError, TypeError):
            logger.debug("Unparseable CVSS v3 vector: %s", v3_vector)

    db_specific = vuln_data.get("database_specific", {})
    if isinstance(db_specific, dict) and "severity" in db_specific:
        raw = str(db_specific["severity"]).lower()
        level = _DATABASE_SEVERITY_LEVELS.get(raw, "unknown")
        return SeverityInfo(
            level=level, score=None, vector=None, source="database_specific"
        )

    return SeverityInfo(level="unknown", score=None, vector=None, source="none")


# --- end CVSS severity scoring ---------------------------------------------


@dataclass
class VulnerableFunction:
    """A function/symbol known to be affected by a vulnerability."""

    name: str
    module: str | None = None

    def to_dict(self) -> dict:
        result: dict = {"name": self.name}
        if self.module:
            result["module"] = self.module
        return result


@dataclass
class Vulnerability:
    """A vulnerability found for a package."""

    id: str
    summary: str
    severity: str
    affected_versions: list[str] = field(default_factory=list)
    vulnerable_functions: list[VulnerableFunction] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    affected_packages: list[dict[str, str]] = field(default_factory=list)
    """Ecosystem/name pairs OSV lists as affected, capped at 20.

    Populated by `OSVScanner.parse_vuln`, but deliberately left out of
    `to_dict`: `sca_scan_dependencies` already ties each vulnerability to
    the single package it scanned, so only `sca_lookup_vulnerability`
    (which has no package context) adds this field to its response.
    """

    def cve_ids(self) -> list[str]:
        """Return CVE identifiers for this vulnerability.

        Includes `id` itself when it matches the strict CVE shape
        (`^CVE-\\d{4}-\\d{4,}$`), plus any aliases matching the same
        shape, de-duplicated while keeping first-seen order. A
        "CVE-"-prefixed alias that does not match the strict shape (for
        example too few digits) is not a real CVE id and is excluded.

        Returns:
            CVE identifiers in first-seen order (`id` before `aliases`),
            with duplicates removed.
        """
        ids: list[str] = []
        if _CVE_ID_RE.match(self.id):
            ids.append(self.id)
        for alias in self.aliases:
            if _CVE_ID_RE.match(alias) and alias not in ids:
                ids.append(alias)
        return ids

    def reachability_check(self) -> dict:
        """Build the question the calling agent answers about its own code."""
        if self.vulnerable_functions:
            check: dict = {
                "symbols": [f.to_dict() for f in self.vulnerable_functions],
                "question": (
                    "Does the code call or import any of these symbols? "
                    "If none are used, the vulnerable code path is likely "
                    "not reached."
                ),
            }
        else:
            check = {
                "symbols": "no_symbol_data",
                "question": (
                    "OSV lists no affected symbols. Read the summary and "
                    "references and judge whether the code uses the "
                    "behavior described."
                ),
            }
        check["answer_with"] = (
            "verdict (reachable | not_reachable | uncertain), confidence "
            "(high | medium | low), and evidence (file:line of each use, or "
            "what you searched). Say not_reachable with high confidence only "
            "after searching the whole project for imports, aliases and "
            "dynamic use of the package; otherwise say uncertain."
        )
        if self.fixed_versions:
            check["if_unsure"] = (
                f"Upgrade to {self.fixed_versions[0]} or later."
                if len(self.fixed_versions) == 1
                else "Upgrade to a fixed version: "
                + ", ".join(self.fixed_versions)
                + "."
            )
        else:
            check["if_unsure"] = "No fixed version listed; avoid the affected API."
        return check

    def to_dict(self, exploit_context: dict[str, Any] | None = None) -> dict:
        """Return this vulnerability as a plain, JSON-serialisable dict.

        Args:
            exploit_context: The `ExploitContext.to_dict()` output for this
                vulnerability, when enrichment ran and found one. Added
                under `"exploit_context"` when given.
        """
        result: dict = {
            "id": self.id,
            "summary": untrusted(self.summary, _SUMMARY_LIMIT),
            "severity": self.severity,
        }
        if self.affected_versions:
            result["affected_versions"] = self.affected_versions
        if self.fixed_versions:
            result["fixed_versions"] = self.fixed_versions
        if self.references:
            result["references"] = self.references
        result["aliases"] = self.aliases
        if self.cvss_score is not None:
            result["cvss_score"] = self.cvss_score
        if self.cvss_vector is not None:
            result["cvss_vector"] = self.cvss_vector
        result["reachability_check"] = self.reachability_check()
        if exploit_context is not None:
            result["exploit_context"] = exploit_context
        return result


@dataclass
class ScanResult:
    """Result of scanning a single package."""

    name: str
    version: str
    ecosystem: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    error: str | None = None
    error_code: str | None = None

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0

    def to_dict(
        self, exploit_contexts: dict[str, dict[str, Any]] | None = None
    ) -> dict:
        """Return this scan result as a plain, JSON-serialisable dict.

        Args:
            exploit_contexts: `ExploitContext.to_dict()` output keyed by
                vulnerability id, passed through to each vulnerability.
        """
        result: dict = {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "vulnerable": self.has_vulnerabilities,
        }
        if self.vulnerabilities:
            result["vulnerability_count"] = len(self.vulnerabilities)
            contexts = exploit_contexts or {}
            result["vulnerabilities"] = [
                v.to_dict(contexts.get(v.id)) for v in self.vulnerabilities
            ]
        if self.error:
            result["error"] = error_body(
                self.error_code or "scan_failed",
                self.error,
                "Retry the scan, or tell the user it could not run.",
            )
        return result


# Map OSV ecosystem names to our input names
_ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "pip": "PyPI",
    "python": "PyPI",
    "npm": "npm",
    "node": "npm",
    "javascript": "npm",
    "js": "npm",
    "go": "Go",
    "cargo": "crates.io",
    "rust": "crates.io",
    "maven": "Maven",
    "java": "Maven",
    "nuget": "NuGet",
    "csharp": "NuGet",
    "rubygems": "RubyGems",
    "ruby": "RubyGems",
    "github-actions": "GitHub Actions",
    "actions": "GitHub Actions",
    "gha": "GitHub Actions",
}


class OSVScanner:
    """Scans packages for vulnerabilities using OSV.dev API."""

    def __init__(self, timeout: float = 15.0) -> None:
        self._timeout = timeout

    async def scan_package(
        self,
        name: str,
        version: str,
        ecosystem: str,
    ) -> ScanResult:
        """Scan a single package for vulnerabilities."""
        results = await self.scan_packages(
            [{"name": name, "version": version, "ecosystem": ecosystem}]
        )
        return results[0]

    async def scan_packages(self, packages: list[dict]) -> list[ScanResult]:
        """Scan multiple packages for vulnerabilities in parallel.

        Fires one /v1/query POST per package concurrently — each
        returns full vulnerability data so no hydration step needed.
        """
        results: list[ScanResult | None] = [None] * len(packages)

        async def scan_into(index: int, pkg: dict) -> None:
            results[index] = await self._scan_one(client, pkg)

        async with (
            httpx.AsyncClient(timeout=self._timeout) as client,
            anyio.create_task_group() as tg,
        ):
            for index, pkg in enumerate(packages):
                tg.start_soon(scan_into, index, pkg)
        return [r for r in results if r is not None]

    async def _scan_one(
        self,
        client: httpx.AsyncClient,
        pkg: dict,
    ) -> ScanResult:
        """Scan a single package using the /v1/query endpoint."""
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        ecosystem = pkg.get("ecosystem", "pypi")
        osv_eco = _ECOSYSTEM_MAP.get(ecosystem.lower().strip(), ecosystem)

        try:
            vulns = await self._query_osv(client, name, version, osv_eco)
        except httpx.HTTPError as e:
            logger.error(f"OSV scan failed for {name}@{version}: {e}")
            return ScanResult(
                name=name,
                version=version,
                ecosystem=ecosystem,
                error=f"OSV API error: {e}",
                error_code="osv_unavailable",
            )

        return ScanResult(
            name=name,
            version=version,
            ecosystem=ecosystem,
            vulnerabilities=vulns,
        )

    async def _query_osv(
        self,
        client: httpx.AsyncClient,
        name: str,
        version: str,
        ecosystem: str,
    ) -> list[Vulnerability]:
        """Query OSV.dev for a single package."""
        payload = {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version,
        }
        resp = await client.post(OSV_QUERY_URL, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return self._parse_vulns(data.get("vulns", []))

    def _parse_vulns(self, vulns_data: list[dict]) -> list[Vulnerability]:
        """Parse OSV vulnerability response into our dataclasses."""
        return [self.parse_vuln(vuln_data) for vuln_data in vulns_data]

    def parse_vuln(self, vuln_data: dict[str, Any]) -> Vulnerability:
        """Parse a single OSV vulnerability record into a `Vulnerability`."""
        severity_info = score_severity(vuln_data)
        aliases = vuln_data.get("aliases", [])
        if not isinstance(aliases, list):
            aliases = []

        return Vulnerability(
            id=vuln_data.get("id", ""),
            summary=vuln_data.get("summary", ""),
            severity=severity_info.level,
            affected_versions=self._extract_affected_versions(vuln_data),
            vulnerable_functions=self._extract_vulnerable_functions(vuln_data),
            fixed_versions=self._extract_fixed_versions(vuln_data),
            references=self._extract_references(vuln_data),
            aliases=aliases,
            cvss_score=severity_info.score,
            cvss_vector=severity_info.vector,
            affected_packages=self._extract_affected_packages(vuln_data),
        )

    async def lookup(
        self, vuln_id: str, *, client: httpx.AsyncClient | None = None
    ) -> Vulnerability | None:
        """Look up a single vulnerability by id via `GET /v1/vulns/{id}`.

        The id is URL-encoded before it is placed in the path, regardless
        of whether the caller already validated its shape, so it can
        never be used to steer the request at a different path.

        Args:
            vuln_id: The OSV, CVE, or GHSA id to look up.
            client: An existing client to reuse. Not closed by this call;
                the caller owns its lifecycle. When omitted, a new one is
                created via `new_client` and closed here, which is fine
                for a single ad hoc lookup - a caller looking up many ids
                should share one client across calls instead.

        Returns:
            The parsed `Vulnerability`, or `None` when OSV has no record
            for this id (HTTP 404).

        Raises:
            FetchError: On any other fetch failure: timeout, connection
                error, a non-404 HTTP error, or a response over the size
                cap.
        """
        url = f"{OSV_API_URL}/vulns/{quote(vuln_id, safe='')}"
        owns_client = client is None
        active_client = (
            client if client is not None else new_client(timeout=self._timeout)
        )
        try:
            data = await fetch_json(active_client, url, max_bytes=_LOOKUP_MAX_BYTES)
        except FetchError as exc:
            if exc.code == "http_404":
                return None
            raise
        finally:
            if owns_client:
                await active_client.aclose()
        return self.parse_vuln(data)

    def _extract_severity(self, vuln_data: dict) -> str:
        """Extract severity from OSV vulnerability data."""
        return score_severity(vuln_data).level

    def _extract_affected_versions(self, vuln_data: dict) -> list[str]:
        """Extract affected version ranges."""
        versions = []
        for affected in vuln_data.get("affected", []):
            for rng in affected.get("ranges", []):
                events = rng.get("events", [])
                introduced = None
                fixed = None
                for event in events:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                if introduced and fixed:
                    versions.append(f">={introduced},<{fixed}")
                elif introduced:
                    versions.append(f">={introduced}")
        return versions

    def _extract_fixed_versions(self, vuln_data: dict) -> list[str]:
        """Extract versions in which the vulnerability is fixed."""
        fixed: list[str] = []
        for affected in vuln_data.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    version = event.get("fixed")
                    if version and version not in fixed:
                        fixed.append(version)
        return fixed

    def _extract_vulnerable_functions(
        self, vuln_data: dict
    ) -> list[VulnerableFunction]:
        """Extract vulnerable function/symbol information from OSV data.

        OSV stores this in affected[].ecosystem_specific.imports
        for PyPI, and affected[].ecosystem_specific for npm.
        """
        functions = []
        seen = set()

        for affected in vuln_data.get("affected", []):
            eco_specific = affected.get("ecosystem_specific", {})

            # PyPI style: imports[].symbols
            imports = eco_specific.get("imports", [])
            for imp in imports:
                module = imp.get("path", "")
                for symbol in imp.get("symbols", []):
                    key = f"{module}.{symbol}"
                    if key not in seen:
                        seen.add(key)
                        functions.append(VulnerableFunction(name=symbol, module=module))

            # npm / generic style: functions[]
            func_list = eco_specific.get("functions", [])
            for func_name in func_list:
                if func_name not in seen:
                    seen.add(func_name)
                    parts = func_name.rsplit(".", 1)
                    if len(parts) == 2:
                        functions.append(
                            VulnerableFunction(name=parts[1], module=parts[0])
                        )
                    else:
                        functions.append(VulnerableFunction(name=func_name))

        return functions

    def _extract_references(self, vuln_data: dict) -> list[str]:
        """Extract reference URLs."""
        refs = []
        for ref in vuln_data.get("references", []):
            url = ref.get("url", "")
            if url:
                refs.append(url)
        return refs[:5]  # Limit to 5 references

    def _extract_affected_packages(self, vuln_data: dict) -> list[dict[str, str]]:
        """Extract the ecosystem/name pairs OSV lists as affected.

        De-duplicated, capped at `_MAX_AFFECTED_PACKAGES`.
        """
        packages: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for affected in vuln_data.get("affected", []):
            pkg = affected.get("package", {})
            name = pkg.get("name")
            ecosystem = pkg.get("ecosystem")
            if not name or not ecosystem:
                continue
            key = (ecosystem, name)
            if key in seen:
                continue
            seen.add(key)
            packages.append({"ecosystem": ecosystem, "name": name})
            if len(packages) >= _MAX_AFFECTED_PACKAGES:
                break
        return packages
