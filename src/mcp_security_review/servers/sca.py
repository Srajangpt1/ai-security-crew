"""SCA (Software Composition Analysis) FastMCP server.

Provides tools for package verification and vulnerability scanning
with reachability analysis. Designed to run parallel with code
security verification during coding workflows.
"""

import json
import logging
from typing import Annotated

from fastmcp import Context, FastMCP
from pydantic import Field

from mcp_security_review.providers.sca import (
    EnvironmentContext,
    EnvMarkerEvaluator,
    LockfileParser,
    OSVScanner,
    PackageRegistry,
)
from mcp_security_review.providers.sca.osv import ReachabilityStatus, ScanResult

logger = logging.getLogger(__name__)

_AI_REACHABILITY_SYSTEM_PROMPT = (
    "You are a security expert performing reachability analysis. "
    "Given a vulnerability description and code snippet, determine whether "
    "the vulnerable behavior is triggered by the code. "
    "Begin your answer with exactly one of: 'yes', 'no', or 'uncertain'. "
    "Then explain your reasoning concisely."
)


async def _resolve_ai_reachability(ctx: Context, results: list[ScanResult]) -> None:
    """Call ctx.sample() for each ai_analysis_required reachability result.

    Updates ReachabilityResult.status in place based on the AI response.
    Silently skips if sampling is not supported by the client.
    """
    for scan_result in results:
        for vuln in scan_result.vulnerabilities:
            for reach in vuln.reachability:
                if (
                    reach.status
                    in (
                        ReachabilityStatus.AI_ANALYSIS_REQUIRED,
                        ReachabilityStatus.DYNAMIC_IMPORT,
                    )
                    and reach.reachability_prompt
                ):
                    try:
                        response = await ctx.sample(
                            reach.reachability_prompt,
                            system_prompt=_AI_REACHABILITY_SYSTEM_PROMPT,
                            max_tokens=400,
                        )
                        answer = response.text.strip()
                        lower = answer.lower()
                        if lower.startswith("yes"):
                            reach.status = ReachabilityStatus.REACHABLE
                        elif lower.startswith("no"):
                            reach.status = ReachabilityStatus.NOT_REACHABLE
                        else:
                            reach.status = ReachabilityStatus.UNCERTAIN
                        reach.evidence = f"AI analysis: {answer}"
                        reach.reachability_prompt = None  # consumed
                    except Exception as e:  # noqa: BLE001
                        logger.warning(
                            "AI reachability sampling failed for %s: %s",
                            vuln.id,
                            e,
                        )


sca_mcp = FastMCP(
    name="SCA MCP Service",
    description=(
        "Software Composition Analysis: package verification "
        "and vulnerability scanning with reachability analysis."
    ),
)


@sca_mcp.tool(tags={"security", "sca", "verification"})
async def verify_packages(
    ctx: Context,
    packages_json: Annotated[
        str,
        Field(
            description=(
                "JSON array of packages to verify. Each object needs: "
                "'name' (package name), 'version' (version string), "
                "'ecosystem' ('pypi' or 'npm'). Example: "
                '[{"name": "requests", "version": "2.31.0", '
                '"ecosystem": "pypi"}]'
            )
        ),
    ],
) -> str:
    """Verify that packages exist and their versions are valid.

    Checks each package against its registry (PyPI, npm). For packages
    that don't exist or have invalid versions, suggests corrections.
    Returns only packages that need fixing — valid packages are silent.

    Use this tool when an AI coding agent introduces new dependencies
    to catch hallucinated or misspelled package names and versions.

    Args:
        ctx: The FastMCP context.
        packages_json: JSON array of package objects to verify.

    Returns:
        JSON with 'all_valid' boolean and 'invalid_packages' list.
        If all packages are valid, returns {"all_valid": true}.
        If any are invalid, returns details and suggested fixes.
    """
    try:
        packages = json.loads(packages_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON: {e}"}, indent=2)

    if not isinstance(packages, list):
        return json.dumps(
            {"error": "Expected a JSON array of package objects"},
            indent=2,
        )

    registry = PackageRegistry()
    results = await registry.verify_packages(packages)

    invalid = [r for r in results if not r.is_valid()]

    if not invalid:
        return json.dumps(
            {
                "all_valid": True,
                "packages_checked": len(results),
            },
            indent=2,
        )

    response: dict = {
        "all_valid": False,
        "packages_checked": len(results),
        "invalid_count": len(invalid),
        "invalid_packages": [r.to_dict() for r in invalid],
        "action_required": (
            "Fix the invalid packages listed above. "
            "Use the suggested corrections where provided."
        ),
    }
    return json.dumps(response, indent=2, ensure_ascii=False)


@sca_mcp.tool(tags={"security", "sca", "vulnerability"})
async def scan_dependencies(
    ctx: Context,
    packages_json: Annotated[
        str,
        Field(
            description=(
                "JSON array of NEW packages to scan. Each object needs: "
                "'name' (package name), 'version' (version string), "
                "'ecosystem' ('pypi' or 'npm'). Example: "
                '[{"name": "pyjwt", "version": "2.4.0", '
                '"ecosystem": "pypi"}]'
            )
        ),
    ],
    code_snippets: Annotated[
        str | None,
        Field(
            description=(
                "Optional JSON array of code snippet strings where "
                "these packages are used. If provided and vulnerabilities "
                "have known affected functions, reachability analysis "
                "will determine if the vulnerable code paths are "
                "actually called. Example: "
                '["import pyjwt\\njwt.decode(token, key, '
                "algorithms=['HS256'])\"]"
            ),
            default=None,
        ),
    ] = None,
) -> str:
    """Scan new dependencies for known vulnerabilities using OSV.dev.

    Queries the OSV.dev database for CVEs affecting the specified
    packages. If code snippets are provided, performs reachability
    analysis to check whether vulnerable functions are actually
    used in the code.

    Run this tool whenever new packages are added during a coding
    workflow. Designed to run in parallel with verify_code_security.

    Args:
        ctx: The FastMCP context.
        packages_json: JSON array of package objects to scan.
        code_snippets: Optional JSON array of code strings for
            reachability analysis.

    Returns:
        JSON with scan results per package, including:
        - Whether vulnerabilities were found
        - CVE details, severity, and affected versions
        - Reachability status (if code was provided)
        - Recommended actions
    """
    try:
        packages = json.loads(packages_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON for packages: {e}"}, indent=2)

    if not isinstance(packages, list):
        return json.dumps(
            {"error": "Expected a JSON array of package objects"},
            indent=2,
        )

    snippets = None
    if code_snippets:
        try:
            snippets = json.loads(code_snippets)
            if not isinstance(snippets, list):
                snippets = [str(snippets)]
        except json.JSONDecodeError:
            # Treat as a single code string
            snippets = [code_snippets]

    scanner = OSVScanner()
    results = await scanner.scan_packages(packages, snippets)

    if snippets:
        await _resolve_ai_reachability(ctx, results)

    vulnerable_results = [r for r in results if r.has_vulnerabilities]
    reachable_results = [r for r in results if r.has_reachable_vulnerabilities]

    response: dict = {
        "packages_scanned": len(results),
        "vulnerable_count": len(vulnerable_results),
    }

    if not vulnerable_results:
        response["status"] = "clean"
        response["message"] = "No known vulnerabilities found in scanned packages."
        return json.dumps(response, indent=2, ensure_ascii=False)

    response["status"] = "vulnerabilities_found"
    response["results"] = [r.to_dict() for r in results if r.has_vulnerabilities]

    if snippets:
        response["reachable_count"] = len(reachable_results)
        if reachable_results:
            response["action_required"] = (
                "URGENT: Vulnerable functions are reachable in your "
                "code. Review the reachability evidence and either "
                "upgrade the affected packages or refactor to avoid "
                "the vulnerable functions."
            )
        else:
            response["recommendation"] = (
                "Vulnerabilities found but affected functions are not "
                "directly reachable in the provided code. Consider "
                "upgrading anyway as a precaution."
            )
    else:
        response["recommendation"] = (
            "Provide code snippets where these packages are used "
            "to enable reachability analysis and determine if "
            "vulnerable functions are actually called."
        )

    return json.dumps(response, indent=2, ensure_ascii=False)


@sca_mcp.tool(tags={"security", "sca", "lockfile", "runtime"})
async def scan_lockfile(
    ctx: Context,
    lockfile_content: Annotated[
        str,
        Field(
            description=(
                "Content of the lockfile to parse and scan. Supported formats: "
                "requirements.txt, uv.lock, poetry.lock, package-lock.json, "
                "yarn.lock, Pipfile.lock."
            )
        ),
    ],
    lockfile_name: Annotated[
        str,
        Field(
            description=(
                "Filename of the lockfile (e.g. 'requirements.txt', 'uv.lock'). "
                "Used to detect format."
            ),
            default="requirements.txt",
        ),
    ] = "requirements.txt",
    target_python_version: Annotated[
        str | None,
        Field(
            description=(
                "Target Python version to evaluate environment markers against, "
                "e.g. '3.11'. Defaults to current interpreter version. "
                "Use this to simulate what's installed in a container."
            ),
            default=None,
        ),
    ] = None,
    target_platform: Annotated[
        str | None,
        Field(
            description=(
                "Target sys.platform for marker evaluation, e.g. 'linux', 'win32', "
                "'darwin'. Defaults to current platform."
            ),
            default=None,
        ),
    ] = None,
    extras: Annotated[
        str | None,
        Field(
            description=(
                "Comma-separated list of package extras to activate when evaluating "
                "optional dependency markers, e.g. 'security,async'."
            ),
            default=None,
        ),
    ] = None,
    code_snippets: Annotated[
        str | None,
        Field(
            description=(
                "Optional JSON array of code snippet strings to enable reachability "
                "analysis on vulnerable packages found in the lockfile."
            ),
            default=None,
        ),
    ] = None,
) -> str:
    """Scan a lockfile to find CVEs in the *actual* resolved dependency graph.

    Addresses the static vs runtime analysis gap by:
    1. Parsing the lockfile to get all *resolved* packages (direct + transitive)
    2. Evaluating PEP 508 environment markers to filter deps inactive in the
       target environment (e.g. Windows-only deps on a Linux container)
    3. Flagging packages installed from non-registry sources (git, path, URL)
       which may diverge from the published version at runtime
    4. Scanning all active packages against OSV.dev for known CVEs
    5. Optionally running reachability analysis if code snippets are provided

    Use this tool when you need to audit what's *actually loaded at runtime*
    rather than just what's declared in pyproject.toml or package.json.

    Args:
        ctx: The FastMCP context.
        lockfile_content: Raw content of the lockfile.
        lockfile_name: Filename hint for format detection.
        target_python_version: Python version to evaluate markers against.
        target_platform: sys.platform for marker evaluation.
        extras: Comma-separated extras to activate.
        code_snippets: Optional JSON array of code for reachability analysis.

    Returns:
        JSON with:
        - Lockfile format detected
        - Total/active/skipped package counts
        - Packages skipped due to inactive env markers
        - Non-registry sources flagged (potential drift)
        - CVE findings with reachability status
    """
    # Parse lockfile
    parse_result = LockfileParser.parse(lockfile_content, lockfile_name)

    if not parse_result.dependencies:
        return json.dumps(
            {
                "format": parse_result.format.value,
                "error": "No pinned packages found in lockfile",
                "warnings": parse_result.warnings,
            },
            indent=2,
        )

    # Build environment context for marker evaluation
    if target_python_version or target_platform:
        env = EnvironmentContext.for_container(
            python_version=target_python_version or "3.11",
            sys_platform=target_platform or "linux",
        )
    else:
        env = EnvironmentContext()

    if extras:
        env.extras = [e.strip() for e in extras.split(",") if e.strip()]

    # Evaluate markers to get the runtime-active subset
    evaluator = EnvMarkerEvaluator()
    active_deps, skipped_reasons = evaluator.filter_active(
        parse_result.dependencies, env
    )

    # Collect non-registry sources (potential drift points)
    drift_warnings = [
        f"{dep.name}@{dep.version}: non-registry source — {dep.source}"
        for dep in active_deps
        if dep.source
    ]

    # Prepare packages for OSV scanning
    packages_to_scan = [
        {"name": dep.name, "version": dep.version, "ecosystem": dep.ecosystem}
        for dep in active_deps
    ]

    # Parse code snippets
    snippets = None
    if code_snippets:
        try:
            snippets = json.loads(code_snippets)
            if not isinstance(snippets, list):
                snippets = [str(snippets)]
        except json.JSONDecodeError:
            snippets = [code_snippets]

    # Scan all active packages
    scanner = OSVScanner()
    scan_results = await scanner.scan_packages(packages_to_scan, snippets)

    if snippets:
        await _resolve_ai_reachability(ctx, scan_results)

    vulnerable = [r for r in scan_results if r.has_vulnerabilities]
    reachable = [r for r in scan_results if r.has_reachable_vulnerabilities]

    response: dict = {
        "lockfile_format": parse_result.format.value,
        "total_packages_in_lockfile": len(parse_result.dependencies),
        "direct_packages": parse_result.direct_count,
        "transitive_packages": parse_result.transitive_count,
        "active_after_marker_eval": len(active_deps),
        "skipped_by_markers": len(skipped_reasons),
        "non_registry_sources": len(drift_warnings),
        "packages_scanned": len(scan_results),
        "vulnerable_count": len(vulnerable),
    }

    if parse_result.warnings:
        response["lockfile_warnings"] = parse_result.warnings

    if skipped_reasons:
        response["marker_filtered_deps"] = skipped_reasons

    if drift_warnings:
        response["runtime_drift_risk"] = drift_warnings
        response["drift_warning"] = (
            "These packages are installed from non-registry sources (git, path, URL). "
            "The resolved version at build time may differ from what's running in "
            "production. Verify these match your expected versions."
        )

    if not vulnerable:
        response["status"] = "clean"
        response["message"] = (
            f"No known vulnerabilities in {len(active_deps)} active packages "
            f"(from {len(parse_result.dependencies)} total in lockfile)."
        )
        return json.dumps(response, indent=2, ensure_ascii=False)

    response["status"] = "vulnerabilities_found"
    response["results"] = [r.to_dict() for r in vulnerable]

    if snippets:
        response["reachable_count"] = len(reachable)
        if reachable:
            response["action_required"] = (
                "URGENT: Vulnerable functions are reachable in your code. "
                "Upgrade the affected packages immediately."
            )
        else:
            response["recommendation"] = (
                "Vulnerabilities found but not directly reachable in the provided "
                "code. Upgrade as a precaution, especially transitive dependencies."
            )
    else:
        response["recommendation"] = (
            "Provide code_snippets to enable reachability analysis and determine "
            "which of these CVEs are actually exploitable in your codebase."
        )

    return json.dumps(response, indent=2, ensure_ascii=False)
