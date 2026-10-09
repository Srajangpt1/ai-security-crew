"""OSV.dev vulnerability scanner with reachability analysis.

Queries the OSV.dev API for known vulnerabilities and checks
whether vulnerable functions are reachable in the provided code.
"""

import asyncio
import logging
import re
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


class ReachabilityStatus:
    """Reachability determination status values."""

    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    NOT_IMPORTED = "not_imported"
    AI_ANALYSIS_REQUIRED = "ai_analysis_required"
    NO_CODE_PROVIDED = "no_code_provided"
    UNCERTAIN = "uncertain"  # AI analyzed but could not definitively determine
    # Package loaded via dynamic import — static analysis cannot confirm
    DYNAMIC_IMPORT = "dynamic_import"


@dataclass
class ReachabilityResult:
    """Result of checking if a vulnerable function is reachable."""

    status: str  # one of ReachabilityStatus values
    evidence: str | None = None
    function: VulnerableFunction | None = None
    reachability_prompt: str | None = None  # set when AI analysis is needed

    @property
    def reachable(self) -> bool:
        return self.status == ReachabilityStatus.REACHABLE

    def to_dict(self) -> dict:
        result: dict = {"status": self.status}
        if self.function:
            result["function"] = self.function.to_dict()
        if self.evidence:
            result["evidence"] = self.evidence
        if self.reachability_prompt:
            result["reachability_prompt"] = self.reachability_prompt
        return result


@dataclass
class Vulnerability:
    """A vulnerability found for a package."""

    id: str
    summary: str
    severity: str
    affected_versions: list[str] = field(default_factory=list)
    vulnerable_functions: list[VulnerableFunction] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    reachability: list[ReachabilityResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        result: dict = {
            "id": self.id,
            "summary": self.summary,
            "severity": self.severity,
        }
        if self.affected_versions:
            result["affected_versions"] = self.affected_versions
        if self.vulnerable_functions:
            result["vulnerable_functions"] = [
                f.to_dict() for f in self.vulnerable_functions
            ]
        if self.references:
            result["references"] = self.references
        if self.reachability:
            result["reachability"] = [r.to_dict() for r in self.reachability]
            statuses = [r.status for r in self.reachability]
            result["reachability_summary"] = (
                ReachabilityStatus.REACHABLE
                if ReachabilityStatus.REACHABLE in statuses
                else (
                    ReachabilityStatus.NOT_REACHABLE
                    if all(
                        s
                        in (
                            ReachabilityStatus.NOT_REACHABLE,
                            ReachabilityStatus.NOT_IMPORTED,
                        )
                        for s in statuses
                    )
                    else statuses[0]
                    if len(set(statuses)) == 1
                    else "mixed"
                )
            )
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

    @property
    def has_reachable_vulnerabilities(self) -> bool:
        return any(
            any(r.reachable for r in v.reachability)
            for v in self.vulnerabilities
            if v.reachability
        )

    @property
    def needs_ai_analysis(self) -> bool:
        return any(
            any(
                r.status == ReachabilityStatus.AI_ANALYSIS_REQUIRED
                for r in v.reachability
            )
            for v in self.vulnerabilities
            if v.reachability
        )

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
            if any(v.reachability for v in self.vulnerabilities):
                result["reachable"] = self.has_reachable_vulnerabilities
                result["needs_ai_reachability_analysis"] = self.needs_ai_analysis
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
        code_snippets: list[str] | None = None,
    ) -> ScanResult:
        """Scan a single package for vulnerabilities."""
        results = await self.scan_packages(
            [{"name": name, "version": version, "ecosystem": ecosystem}],
            code_snippets,
        )
        return results[0]

    async def scan_packages(
        self,
        packages: list[dict],
        code_snippets: list[str] | None = None,
    ) -> list[ScanResult]:
        """Scan multiple packages for vulnerabilities in parallel.

        Fires one /v1/query POST per package concurrently — each
        returns full vulnerability data so no hydration step needed.
        """
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            tasks = [self._scan_one(client, pkg, code_snippets) for pkg in packages]
            return list(await asyncio.gather(*tasks))

    async def _scan_one(
        self,
        client: httpx.AsyncClient,
        pkg: dict,
        code_snippets: list[str] | None,
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

        if vulns:
            combined_code = "\n".join(code_snippets) if code_snippets else ""
            for vuln in vulns:
                vuln.reachability = self._determine_reachability(
                    vuln,
                    name,
                    osv_eco,
                    combined_code,
                    has_code=bool(code_snippets),
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
            references = self._extract_references(vuln_data)

            vulnerabilities.append(
                Vulnerability(
                    id=vuln_id,
                    summary=summary,
                    severity=severity,
                    affected_versions=affected_versions,
                    vulnerable_functions=vulnerable_functions,
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

    def _determine_reachability(
        self,
        vuln: "Vulnerability",
        package_name: str,
        ecosystem: str,
        code: str,
        *,
        has_code: bool = True,
    ) -> list[ReachabilityResult]:
        """Determine reachability for a vulnerability.

        Decision tree:
        1. No code provided → no_code_provided
        2. Package not imported → not_imported
        3. OSV has function symbols → static check → reachable/not_reachable
        4. No function symbols → keyword check → reachable or ai_analysis_required
        """
        if not has_code:
            return [
                ReachabilityResult(
                    status=ReachabilityStatus.NO_CODE_PROVIDED,
                    evidence=(
                        "No code snippets provided. Pass code_snippets "
                        "to enable reachability analysis."
                    ),
                )
            ]

        # Step 1: Is the package imported at all?
        # Collect alternative import names from vuln module data
        # (e.g. pyjwt package is imported as "jwt")
        alt_names = {
            vf.module.split(".")[0]
            for vf in vuln.vulnerable_functions
            if vf.module and vf.module.split(".")[0] != package_name
        }
        imported, import_evidence = self._is_package_imported(
            package_name, ecosystem, code, alt_names
        )
        if not imported:
            return [
                ReachabilityResult(
                    status=ReachabilityStatus.NOT_IMPORTED,
                    evidence=import_evidence,
                )
            ]

        # If import was detected via a dynamic pattern, flag it and ask AI
        if import_evidence and import_evidence.startswith("DYNAMIC:"):
            prompt = self._build_ai_reachability_prompt(
                vuln, package_name, code, import_evidence
            )
            return [
                ReachabilityResult(
                    status=ReachabilityStatus.DYNAMIC_IMPORT,
                    evidence=(
                        f"{package_name} appears to be loaded dynamically — "
                        "static analysis cannot confirm reachability. "
                        f"{import_evidence}"
                    ),
                    reachability_prompt=prompt,
                )
            ]

        # Step 2: OSV gave us specific function symbols — do static check
        if vuln.vulnerable_functions:
            results = []
            for vfunc in vuln.vulnerable_functions:
                reachable, evidence = self._is_function_called(
                    vfunc, code, package_name, ecosystem
                )
                results.append(
                    ReachabilityResult(
                        status=(
                            ReachabilityStatus.REACHABLE
                            if reachable
                            else ReachabilityStatus.NOT_REACHABLE
                        ),
                        function=vfunc,
                        evidence=evidence or import_evidence,
                    )
                )
            return results

        # Step 3: No function symbols — try keyword match, then ask AI
        keyword_match = self._keyword_match(vuln.summary, code)
        if keyword_match:
            return [
                ReachabilityResult(
                    status=ReachabilityStatus.REACHABLE,
                    evidence=(
                        f"Keyword match in code: '{keyword_match}' "
                        f"(from vuln summary). {import_evidence}"
                    ),
                )
            ]

        # Step 4: Package is imported, no function data, no keyword match
        # → hand off to AI agent with a structured prompt
        prompt = self._build_ai_reachability_prompt(
            vuln, package_name, code, import_evidence or ""
        )
        return [
            ReachabilityResult(
                status=ReachabilityStatus.AI_ANALYSIS_REQUIRED,
                evidence=(
                    f"{package_name} is imported but OSV has no "
                    f"function-level data for {vuln.id}. "
                    "AI analysis required to determine reachability."
                ),
                reachability_prompt=prompt,
            )
        ]

    def _is_package_imported(
        self,
        package_name: str,
        ecosystem: str,
        code: str,
        alt_names: set[str] | None = None,
    ) -> tuple[bool, str | None]:
        """Check if a package is imported anywhere in the code.

        alt_names: alternative import names (e.g. pyjwt -> {"jwt"}).

        Also detects dynamic imports (importlib, __import__, require() with
        variable arg) and returns a sentinel evidence string so the caller
        can flag the result as DYNAMIC_IMPORT status.
        """
        names_to_check = [package_name] + list(alt_names or set())

        if ecosystem == "PyPI":
            for name in names_to_check:
                patterns = [
                    rf"^import\s+{re.escape(name)}\b",
                    rf"^from\s+{re.escape(name)}\b",
                ]
                for p in patterns:
                    m = re.search(p, code, re.MULTILINE | re.IGNORECASE)
                    if m:
                        return True, f"Imported: {m.group().strip()}"

            # Dynamic import patterns for Python
            dyn_evidence = self._find_dynamic_import(
                package_name, ecosystem, code, alt_names
            )
            if dyn_evidence:
                return True, dyn_evidence

            return False, f"'{package_name}' not found in any import statement"

        elif ecosystem == "npm":
            for name in names_to_check:
                pkg = re.escape(name)
                patterns = [
                    rf"""require\s*\(\s*['\"]{pkg}['\\"]\s*\)""",
                    rf"""from\s+['\"]{pkg}['\"]""",
                ]
                for p in patterns:
                    m = re.search(p, code)
                    if m:
                        return True, f"Imported: {m.group().strip()}"

            # Dynamic import patterns for JS/TS
            dyn_evidence = self._find_dynamic_import(
                package_name, ecosystem, code, alt_names
            )
            if dyn_evidence:
                return True, dyn_evidence

            return False, f"'{package_name}' not found in any import/require"

        else:
            for name in names_to_check:
                if re.search(re.escape(name), code, re.IGNORECASE):
                    return True, f"'{name}' referenced in code"
            return False, f"'{package_name}' not referenced in code"

    def _find_dynamic_import(
        self,
        package_name: str,
        ecosystem: str,
        code: str,
        alt_names: set[str] | None = None,
    ) -> str | None:
        """Detect dynamic import patterns that static regex misses.

        Returns an evidence string prefixed with 'DYNAMIC:' if found,
        None otherwise.

        Python patterns detected:
        - importlib.import_module("pkg") / importlib.import_module('pkg')
        - __import__("pkg")
        - importlib.import_module(variable)  — flagged as uncertain
        - exec()/eval() calls  — flagged as uncertain if package name nearby

        JS/TS patterns detected:
        - import("pkg")  dynamic import()
        - require(variable)  — flagged as uncertain
        - require.resolve("pkg")
        - await import("pkg")
        """
        names_to_check = [package_name] + list(alt_names or set())

        if ecosystem == "PyPI":
            for name in names_to_check:
                pkg = re.escape(name)
                # importlib.import_module("pkg") or importlib.import_module('pkg')
                m = re.search(
                    rf"""importlib\.import_module\s*\(\s*['\"]{pkg}['\"]""",
                    code,
                )
                if m:
                    matched = m.group().strip()
                    return f"DYNAMIC: importlib.import_module('{name}') — {matched}"

                # __import__("pkg")
                m = re.search(
                    rf"""__import__\s*\(\s*['\"]{pkg}['\"]""",
                    code,
                )
                if m:
                    return f"DYNAMIC: __import__('{name}') — {m.group().strip()}"

            # Generic dynamic load indicators (uncertain — no specific package name)
            # importlib.import_module(variable) where variable might contain our pkg
            if re.search(r"importlib\.import_module\s*\(\s*[^'\"]", code):
                return (
                    f"DYNAMIC: importlib.import_module(variable) detected — "
                    f"cannot confirm if '{package_name}' is loaded dynamically"
                )
            # exec/eval with package name appearing in the expression
            for name in names_to_check:
                m = re.search(
                    rf"""(?:exec|eval)\s*\([\s\S]{{0,500}}?\b{re.escape(name)}\b""",
                    code,
                )
                if m:
                    return (
                        f"DYNAMIC: exec/eval with '{name}' reference — "
                        f"package may be loaded dynamically"
                    )

        elif ecosystem == "npm":
            for name in names_to_check:
                pkg = re.escape(name)
                # Dynamic import(): import("pkg") or await import("pkg")
                m = re.search(
                    rf"""import\s*\(\s*['\"]{pkg}['\"]""",
                    code,
                )
                if m:
                    return f"DYNAMIC: import('{name}') — {m.group().strip()}"

                # require.resolve("pkg")
                m = re.search(
                    rf"""require\.resolve\s*\(\s*['\"]{pkg}['\"]""",
                    code,
                )
                if m:
                    return f"DYNAMIC: require.resolve('{name}') — {m.group().strip()}"

            # require(variable) — uncertain
            if re.search(r"require\s*\(\s*[^'\"`]", code):
                return (
                    f"DYNAMIC: require(variable) detected — "
                    f"cannot confirm if '{package_name}' is loaded dynamically"
                )

        return None

    def _is_function_called(
        self,
        vfunc: VulnerableFunction,
        code: str,
        package_name: str,
        ecosystem: str,
    ) -> tuple[bool, str | None]:
        """Check if a specific vulnerable function is called in code."""
        func_name = vfunc.name
        module = vfunc.module

        # Also check the module's top-level name for import matching
        # (e.g. pyjwt's module is "jwt")
        names_to_check = [package_name]
        if module:
            top = module.split(".")[0]
            if top != package_name:
                names_to_check.append(top)

        if ecosystem == "PyPI":
            # from X import func_name
            m = re.search(
                rf"from\s+\S+\s+import\s+[^;\n]*\b{re.escape(func_name)}\b",
                code,
                re.MULTILINE,
            )
            if m:
                return True, f"Imported directly: {m.group().strip()}"

            # obj.func_name( or func_name(
            m = re.search(
                rf"\b\w*\.?{re.escape(func_name)}\s*\(",
                code,
            )
            if m:
                return True, f"Called: {m.group().strip()}"

            return (
                False,
                f"'{func_name}' not directly called "
                f"(package '{package_name}' is imported)",
            )

        elif ecosystem == "npm":
            m = re.search(rf"\.{re.escape(func_name)}\s*\(", code)
            if m:
                return True, f"Called: {m.group().strip()}"
            m = re.search(rf"\b{re.escape(func_name)}\s*\(", code)
            if m:
                return True, f"Called: {m.group().strip()}"
            return (
                False,
                f"'{func_name}' not directly called "
                f"(package '{package_name}' is imported)",
            )

        else:
            if re.search(r"\b" + re.escape(func_name) + r"\b", code):
                return True, f"'{func_name}' found in code"
            return False, None

    def _keyword_match(self, summary: str, code: str) -> str | None:
        """Extract API/class names from vuln summary and search code.

        Looks for CamelCase identifiers, snake_case function names,
        and quoted terms mentioned in the advisory summary.
        """
        candidates: list[str] = []

        # Quoted terms: 'FileResponse', ``yaml.load``, "xmlattr"
        candidates += re.findall(r"[`'\"]([A-Za-z][\w.]+)[`'\"]", summary)

        # CamelCase class names: FileResponse, MultiPartParser
        candidates += re.findall(r"\b([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b", summary)

        # snake_case function calls mentioned: yaml.load, safe_load
        candidates += re.findall(r"\b([a-z_]+\.[a-z_]+)\b", summary)

        for candidate in candidates:
            if len(candidate) < 4:
                continue
            if re.search(re.escape(candidate), code):
                return candidate

        return None

    def _build_ai_reachability_prompt(
        self,
        vuln: "Vulnerability",
        package_name: str,
        code: str,
        import_evidence: str,
    ) -> str:
        """Build a structured prompt for the AI agent to assess reachability."""
        # Trim code to avoid huge prompts
        code_preview = code[:2000] + ("..." if len(code) > 2000 else "")
        return (
            f"## Reachability Analysis Required\n\n"
            f"**Vulnerability**: {vuln.id}\n"
            f"**Package**: {package_name}\n"
            f"**Summary**: {vuln.summary}\n"
            f"**Severity**: {vuln.severity}\n"
            f"**Affected versions**: "
            f"{', '.join(vuln.affected_versions) or 'see references'}\n"
            f"**Import evidence**: {import_evidence}\n\n"
            f"OSV does not provide function-level data for this vulnerability.\n"
            f"Based on the vulnerability description above, determine whether\n"
            f"the code below triggers the vulnerable behavior:\n\n"
            f"```\n{code_preview}\n```\n\n"
            f"Answer:\n"
            f"- Is the vulnerable behavior triggered? (yes / no / uncertain)\n"
            f"- What specific code pattern causes or avoids it?\n"
            f"- Recommended action if reachable."
        )
