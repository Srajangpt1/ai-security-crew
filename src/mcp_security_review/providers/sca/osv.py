"""OSV.dev vulnerability scanner.

Queries the OSV.dev API for known vulnerabilities. Each vulnerability
carries a reachability check (affected symbols plus a question) that the
calling agent answers by reading its own code; the server does not
decide reachability.
"""

import asyncio
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1"
OSV_QUERY_URL = f"{OSV_API_URL}/query"


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

    def to_dict(self) -> dict:
        result: dict = {
            "id": self.id,
            "summary": self.summary,
            "severity": self.severity,
        }
        if self.affected_versions:
            result["affected_versions"] = self.affected_versions
        if self.fixed_versions:
            result["fixed_versions"] = self.fixed_versions
        if self.references:
            result["references"] = self.references
        result["reachability_check"] = self.reachability_check()
        return result


@dataclass
class ScanResult:
    """Result of scanning a single package."""

    name: str
    version: str
    ecosystem: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    error: str | None = None

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0

    def to_dict(self) -> dict:
        result: dict = {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "vulnerable": self.has_vulnerabilities,
        }
        if self.vulnerabilities:
            result["vulnerability_count"] = len(self.vulnerabilities)
            result["vulnerabilities"] = [v.to_dict() for v in self.vulnerabilities]
        if self.error:
            result["error"] = self.error
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
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            tasks = [self._scan_one(client, pkg) for pkg in packages]
            return list(await asyncio.gather(*tasks))

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
        vulnerabilities = []
        for vuln_data in vulns_data:
            vuln_id = vuln_data.get("id", "")
            summary = vuln_data.get("summary", "")
            severity = self._extract_severity(vuln_data)
            affected_versions = self._extract_affected_versions(vuln_data)
            vulnerable_functions = self._extract_vulnerable_functions(vuln_data)
            fixed_versions = self._extract_fixed_versions(vuln_data)
            references = self._extract_references(vuln_data)

            vulnerabilities.append(
                Vulnerability(
                    id=vuln_id,
                    summary=summary,
                    severity=severity,
                    affected_versions=affected_versions,
                    vulnerable_functions=vulnerable_functions,
                    fixed_versions=fixed_versions,
                    references=references,
                )
            )
        return vulnerabilities

    def _extract_severity(self, vuln_data: dict) -> str:
        """Extract severity from OSV vulnerability data."""
        severity_list = vuln_data.get("severity", [])
        for sev in severity_list:
            if sev.get("type") == "CVSS_V3":
                score_str = sev.get("score", "")
                # Parse CVSS vector for score
                if "CVSS:" in score_str:
                    return self._cvss_to_level(score_str)
                return score_str

        # Fallback: check database_specific
        db_specific = vuln_data.get("database_specific", {})
        if "severity" in db_specific:
            return db_specific["severity"].lower()

        return "unknown"

    def _cvss_to_level(self, cvss_vector: str) -> str:
        """Convert CVSS vector string to severity level.

        Parses the base score from common CVSS v3 patterns.
        """
        # Try to find a numeric score in the vector
        # CVSS vectors don't contain scores directly,
        # but some APIs include them
        parts = cvss_vector.split("/")
        for part in parts:
            if part.startswith("AV:"):
                continue
            try:
                score = float(part)
                if score >= 9.0:
                    return "critical"
                elif score >= 7.0:
                    return "high"
                elif score >= 4.0:
                    return "medium"
                else:
                    return "low"
            except ValueError:
                continue
        return "unknown"

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
