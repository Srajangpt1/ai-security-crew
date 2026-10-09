"""SCA (Software Composition Analysis) FastMCP server.

Provides tools for package verification and vulnerability scanning. Designed to run parallel with code
security verification during coding workflows.
"""

import json
import logging
from typing import Annotated

from fastmcp import Context, FastMCP
from pydantic import Field

from mcp_security_review.providers.sca import OSVScanner, PackageRegistry

logger = logging.getLogger(__name__)

sca_mcp = FastMCP(
    name="SCA MCP Service",
    description=(
        "Software Composition Analysis: package verification "
        "and vulnerability scanning."
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
) -> str:
    """Scan new dependencies for known vulnerabilities using OSV.dev.

    Queries OSV.dev for CVEs affecting the given packages. Each finding
    includes a `reachability_check`: the affected symbols (when OSV has
    them) and a question. Answer it by reading your own code. If the
    code does not use the affected symbols, the vulnerability is likely
    not reached; if it does, or you cannot tell, upgrade to the fixed
    version.

    Run this whenever new packages are added. No code is sent to this
    tool.

    Args:
        ctx: The FastMCP context.
        packages_json: JSON array of package objects to scan.

    Returns:
        JSON with scan results per package: vulnerabilities, severity,
        affected and fixed versions, and the reachability check.
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

    scanner = OSVScanner()
    results = await scanner.scan_packages(packages)

    vulnerable_results = [r for r in results if r.has_vulnerabilities]

    response: dict = {
        "packages_scanned": len(results),
        "vulnerable_count": len(vulnerable_results),
    }

    failed = [r for r in results if r.error]
    if failed:
        response["errors"] = [
            {"name": r.name, "version": r.version, "error": r.error} for r in failed
        ]

    if not vulnerable_results:
        if failed:
            response["status"] = "scan_incomplete"
            response["message"] = (
                "Some packages could not be scanned, so this is not a clean "
                "result. Retry, or tell the user the scan could not run."
            )
            return json.dumps(response, indent=2, ensure_ascii=False)
        response["status"] = "clean"
        response["message"] = "No known vulnerabilities found in scanned packages."
        return json.dumps(response, indent=2, ensure_ascii=False)

    response["status"] = "vulnerabilities_found"
    response["results"] = [r.to_dict() for r in vulnerable_results]
    response["action_required"] = (
        "For each vulnerability, answer its reachability_check from your "
        "own code. Upgrade to the fixed version when the affected "
        "symbols are used or you cannot tell; otherwise note it and "
        "consider upgrading anyway."
    )
    return json.dumps(response, indent=2, ensure_ascii=False)
