"""SCA (Software Composition Analysis) FastMCP server.

Provides tools for package verification and vulnerability scanning. Designed to run parallel with code
security verification during coding workflows.
"""

import json
import logging
import re
from typing import Annotated, Any

import anyio
import httpx
from fastmcp import Context, FastMCP
from pydantic import Field

from mcp_security_review.errors import tool_error
from mcp_security_review.providers.intel import (
    ExploitContext,
    PackageAssessment,
    assess_package,
    build_exploit_contexts,
    new_client,
)
from mcp_security_review.providers.sca import OSVScanner, PackageRegistry
from mcp_security_review.providers.sca.osv import Vulnerability

logger = logging.getLogger(__name__)

_PACKAGES_EXAMPLE = '[{"name": "requests", "version": "2.31.0", "ecosystem": "pypi"}]'

_VULN_ID_RE = re.compile(
    r"^(CVE-\d{4}-\d{4,}"
    r"|GHSA(-[23456789cfghjmpqrvwx]{4}){3}"
    r"|[A-Z][A-Z0-9]*-[A-Za-z0-9._:-]{1,64})$"
)
_MAX_LOOKUP_IDS = 20
_MAX_ASSESS_PACKAGES = 25
_UNVERIFIED_STATUSES = frozenset(
    {
        "unverified_sha",
        "cannot_verify_anonymously",
        "unsafe_host",
        "registry_unresolvable",
    }
)


def _split_vulnerability_ids(raw: str) -> list[str]:
    """Split on commas/whitespace, drop empties, de-duplicate in order."""
    seen: set[str] = set()
    ids: list[str] = []
    for part in re.split(r"[,\s]+", raw.strip()):
        if not part or part in seen:
            continue
        seen.add(part)
        ids.append(part)
    return ids


def _parse_packages(packages_json: str) -> list[dict] | str:
    """Parse the packages argument, or return the JSON error to send back."""
    try:
        packages = json.loads(packages_json)
    except json.JSONDecodeError as e:
        return tool_error(
            "invalid_json",
            f"packages_json is not valid JSON: {e}",
            f"Pass a JSON array, for example {_PACKAGES_EXAMPLE}",
        )
    if not isinstance(packages, list) or not all(
        isinstance(p, dict)
        and isinstance(p.get("name"), str)
        and isinstance(p.get("version"), str)
        and p["name"]
        and p["version"]
        and isinstance(p.get("ecosystem", "pypi"), str)
        for p in packages
    ):
        return tool_error(
            "invalid_packages",
            "packages_json must be a JSON array of objects with string "
            "name and version (and, if given, a string ecosystem).",
            f"Pass a JSON array, for example {_PACKAGES_EXAMPLE}",
        )
    return packages


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
                "'name', 'version', and 'ecosystem': 'pypi', 'npm', "
                "'github-actions' (name 'owner/repo[/path]', version a tag, "
                "branch, or commit SHA), or 'container' (name "
                "'[registry/]repository', version a tag or sha256 digest). "
                'Example: [{"name": "requests", "version": "2.31.0", '
                '"ecosystem": "pypi"}, {"name": "actions/checkout", '
                '"version": "v4", "ecosystem": "github-actions"}]'
            )
        ),
    ],
) -> str:
    """Verify that packages exist and their versions are valid.

    Checks each package against its registry (PyPI, npm, GitHub for
    Actions, the image's OCI registry for containers). For packages that
    don't exist or have invalid versions, suggests corrections. Actions
    and images referenced by a tag or branch are valid but listed under
    `unpinned` with a `suggested_fix` that pins them to a commit SHA or
    image digest.

    Use this tool when an AI coding agent introduces new dependencies,
    workflow actions, or base images to catch hallucinated or misspelled
    names and versions.

    Args:
        ctx: The FastMCP context.
        packages_json: JSON array of package objects to verify.

    Returns:
        JSON with 'all_valid' (false only when something is definitely
        missing or a check errored) and 'packages_checked', plus
        when relevant: 'invalid_packages' with suggested fixes, 'errors',
        'unpinned' (valid but movable refs, each with 'suggested_fix'),
        'unverified' (inconclusive checks, each with 'status' and
        'note'), and 'action_required'.
    """
    packages = _parse_packages(packages_json)
    if isinstance(packages, str):
        return packages

    registry = PackageRegistry()
    results = await registry.verify_packages(packages)

    failed = [r for r in results if r.error]
    checked = [r for r in results if not r.error]
    invalid = [r for r in checked if not r.is_valid()]
    unpinned = [r for r in checked if r.is_valid() and r.pinned is False]
    unverified = [r for r in checked if r.status in _UNVERIFIED_STATUSES]

    response: dict[str, Any] = {
        "all_valid": not failed and not invalid,
        "packages_checked": len(results),
    }
    actions: list[str] = []
    if failed:
        response["invalid_packages"] = [r.to_dict() for r in invalid]
        response["errors"] = [r.to_dict() for r in failed]
        actions.append(
            "Some packages could not be verified, which is not the same "
            "as invalid. Follow each error's hint."
        )
    elif invalid:
        response["invalid_count"] = len(invalid)
        response["invalid_packages"] = [r.to_dict() for r in invalid]
        actions.append(
            "Fix the invalid packages listed above. "
            "Use the suggested corrections where provided."
        )
    if unpinned:
        response["unpinned"] = [r.to_dict() for r in unpinned]
        actions.append(
            "Replace each unpinned reference with its suggested_fix: a tag "
            "or branch can be moved to different code, a commit SHA or "
            "image digest cannot."
        )
    if unverified:
        response["unverified"] = [r.to_dict() for r in unverified]
        actions.append(
            "Entries under unverified are not confirmed missing; follow each note."
        )
    if actions:
        response["action_required"] = " ".join(actions)
    return json.dumps(response, indent=2, ensure_ascii=False)


def _failed_assessment(pkg: dict) -> PackageAssessment:
    """A fallback assessment for a package whose assessment raised.

    `assess_package` is documented not to raise; this is the last-resort
    fallback so a bug in one package's assessment never fails the batch
    or the whole tool call.
    """
    return PackageAssessment(
        name=str(pkg.get("name", "")),
        version=str(pkg.get("version", "")),
        ecosystem=str(pkg.get("ecosystem", "pypi")),
        exists=False,
        deprecated=None,
        deprecated_reason=None,
        licenses=[],
        license_class="unknown",
        advisories=[],
        provenance=None,
        source_repo=None,
        scorecard=None,
        dependencies=None,
        adoption_notes=[],
        sources={"deps_dev": "unavailable: error"},
    )


@sca_mcp.tool(tags={"security", "sca", "assessment"})
async def assess_packages(
    ctx: Context,
    packages_json: Annotated[
        str,
        Field(
            description=(
                "JSON array of packages to assess before adopting them. "
                "Each object needs: 'name', 'version', and 'ecosystem': "
                "'pypi', 'npm', or 'github-actions' (name 'owner/repo', "
                "version the action's ref). 'container' and other "
                "ecosystems are not supported and are noted, not scanned. "
                "Up to 25 packages per call. Example: "
                '[{"name": "requests", "version": "2.31.0", '
                '"ecosystem": "pypi"}]'
            )
        ),
    ],
) -> str:
    """Gather pre-adoption signal for packages from deps.dev and Scorecard.

    For each package, reports its license and license class, whether the
    registry marks it deprecated, SLSA provenance or attestation, the
    OpenSSF Scorecard for its source repository (score, date, and its
    weakest checks), and its dependency-graph shape (direct and
    transitive counts, and any deprecated direct dependencies).

    This is not a verdict and not an existence check (use
    `sca_verify_packages` for that): it is signal for a human or agent to
    weigh before adopting a new dependency. Every source is best effort;
    a failure on one source, or one package, never affects the others.

    Args:
        ctx: The FastMCP context.
        packages_json: JSON array of package objects to assess.

    Returns:
        JSON with `packages_assessed` and `results` (one assessment per
        package, each with `adoption_notes` flagging concerns such as
        deprecation, missing provenance, a low Scorecard, a copyleft or
        unknown license, or a large or deprecated dependency tree).
    """
    packages = _parse_packages(packages_json)
    if isinstance(packages, str):
        return packages
    if len(packages) > _MAX_ASSESS_PACKAGES:
        return tool_error(
            "too_many_packages",
            f"Got {len(packages)} packages; at most "
            f"{_MAX_ASSESS_PACKAGES} are allowed per call.",
            "Split the packages across multiple calls.",
        )

    client = new_client()
    try:
        results: list[PackageAssessment] = []
        for pkg in packages:
            try:
                result = await assess_package(
                    client,
                    pkg["name"],
                    pkg["version"],
                    pkg.get("ecosystem", "pypi"),
                )
            except Exception:  # a bad package must not fail the whole batch
                logger.exception("Package assessment failed for %s", pkg.get("name"))
                result = _failed_assessment(pkg)
            results.append(result)
    finally:
        await client.aclose()

    response: dict[str, Any] = {
        "success": True,
        "packages_assessed": len(results),
        "results": [r.to_dict() for r in results],
        "instructions": (
            "These are inputs to weigh, not a verdict. Raise copyleft, "
            "deprecated, or low-Scorecard packages with the user before "
            "adopting them."
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
                "'ecosystem' ('pypi', 'npm', or 'github-actions' with name "
                "'owner/repo' and the action's version). Example: "
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
    packages = _parse_packages(packages_json)
    if isinstance(packages, str):
        return packages

    scanner = OSVScanner()
    results = await scanner.scan_packages(packages)

    vulnerable_results = [r for r in results if r.has_vulnerabilities]

    response: dict = {
        "packages_scanned": len(results),
        "vulnerable_count": len(vulnerable_results),
    }

    failed = [r for r in results if r.error]
    if failed:
        response["errors"] = [r.to_dict() for r in failed]

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

    all_vulns = [v for r in vulnerable_results for v in r.vulnerabilities]
    exploit_contexts = await _exploit_contexts_for(all_vulns)

    response["status"] = "vulnerabilities_found"
    response["results"] = [
        r.to_dict(
            {
                v.id: exploit_contexts[v.id].to_dict()
                for v in r.vulnerabilities
                if v.id in exploit_contexts
            }
        )
        for r in vulnerable_results
    ]
    response["upgrade_now"] = _upgrade_now_ids(all_vulns, exploit_contexts)
    response["action_required"] = (
        "For each vulnerability, answer its reachability_check from your "
        "own code. Upgrade to the fixed version when the affected "
        "symbols are used or you cannot tell; otherwise note it and "
        "consider upgrading anyway. Upgrade every id in upgrade_now "
        "whatever the reachability answer: it is in CISA KEV or in the "
        "top 10% of EPSS."
    )
    return json.dumps(response, indent=2, ensure_ascii=False)


@sca_mcp.tool(tags={"security", "sca", "vulnerability"})
async def lookup_vulnerability(
    ctx: Context,
    vulnerability_ids: Annotated[
        str,
        Field(
            description=(
                "One or more vulnerability ids to look up directly, "
                "separated by commas or whitespace (CVE-YYYY-NNNN, "
                "GHSA-xxxx-xxxx-xxxx, or another OSV id). Up to 20 ids "
                "per call. Example: "
                '"CVE-2021-44228, GHSA-jfh8-c2jp-5v3q"'
            )
        ),
    ],
) -> str:
    """Look up known vulnerabilities by id, without scanning a package.

    Use this when a vulnerability id is already known (from a report, an
    advisory link, or a previous scan) and a package-level scan is not
    needed. Each id is checked against OSV.dev independently; a failure
    on one id does not stop the others.

    Args:
        ctx: The FastMCP context.
        vulnerability_ids: Ids to look up, comma- or whitespace-separated.

    Returns:
        JSON with `results`: one entry per requested id, in request
        order. Every entry carries `requested_id` (the exact string the
        caller passed) and `status` (`found`, `not_found`, `invalid_id`,
        or `lookup_failed`). A `found` entry also carries OSV's canonical
        `id` (which can differ from `requested_id`, e.g. an alias), the
        vulnerability's details (minus the reachability_check, which
        needs a package context this tool does not have), its
        `affected_packages`, and `exploit_context`. `upgrade_now` lists
        canonical ids CISA KEV or top-EPSS flags.
    """
    ids = _split_vulnerability_ids(vulnerability_ids)
    if len(ids) > _MAX_LOOKUP_IDS:
        return tool_error(
            "too_many_ids",
            f"Got {len(ids)} ids; at most {_MAX_LOOKUP_IDS} are allowed per call.",
            "Split the ids across multiple calls.",
        )

    statuses: dict[str, str] = {}
    valid_ids: list[str] = []
    for vuln_id in ids:
        if _VULN_ID_RE.match(vuln_id):
            valid_ids.append(vuln_id)
        else:
            statuses[vuln_id] = "invalid_id"

    scanner = OSVScanner()
    vulns: dict[str, Vulnerability] = {}
    client = new_client()
    try:
        async with anyio.create_task_group() as tg:
            for vuln_id in valid_ids:
                tg.start_soon(_lookup_one, scanner, client, vuln_id, statuses, vulns)
    finally:
        await client.aclose()

    exploit_contexts = await _exploit_contexts_for(list(vulns.values()))

    results: list[dict[str, Any]] = []
    for vuln_id in ids:
        status = statuses[vuln_id]
        entry: dict[str, Any] = {"requested_id": vuln_id}
        if status != "found":
            entry["status"] = status
            results.append(entry)
            continue
        vuln = vulns[vuln_id]
        context = exploit_contexts.get(vuln.id)
        entry.update(vuln.to_dict(context.to_dict() if context else None))
        entry.pop("reachability_check", None)
        entry["status"] = "found"
        entry["affected_packages"] = vuln.affected_packages
        results.append(entry)

    response: dict[str, Any] = {
        "success": True,
        "results": results,
        "upgrade_now": _upgrade_now_ids(list(vulns.values()), exploit_contexts),
    }
    return json.dumps(response, indent=2, ensure_ascii=False)


async def _lookup_one(
    scanner: OSVScanner,
    client: httpx.AsyncClient,
    vuln_id: str,
    statuses: dict[str, str],
    vulns: dict[str, Vulnerability],
) -> None:
    """Look up one id against the shared client, isolating its failure.

    Writes its outcome into `statuses` (and `vulns` when found) keyed by
    `vuln_id`. Every `vuln_id` passed in across the batch is distinct, so
    concurrent writes never collide. A failure here must not fail the
    rest of the batch, hence the broad catch.
    """
    try:
        vuln = await scanner.lookup(vuln_id, client=client)
    except Exception:  # a bad id or upstream hiccup must not fail the batch
        logger.exception("OSV lookup failed for %s", vuln_id)
        statuses[vuln_id] = "lookup_failed"
        return
    if vuln is None:
        statuses[vuln_id] = "not_found"
        return
    statuses[vuln_id] = "found"
    vulns[vuln_id] = vuln


async def _exploit_contexts_for(
    vulns: list[Vulnerability],
) -> dict[str, ExploitContext]:
    """Build exploit context for `vulns`, owning the client's lifecycle.

    Shared by `scan_dependencies` and `lookup_vulnerability`. Never
    raises: enrichment is best effort, so a failure falls back to
    `_unavailable_contexts` instead of failing the caller's tool call.
    """
    client = new_client()
    try:
        return await build_exploit_contexts(vulns, client=client)
    except Exception:  # enrichment is best effort; the caller must not fail
        logger.exception("Exploit context enrichment failed")
        return _unavailable_contexts(vulns)
    finally:
        await client.aclose()


def _upgrade_now_ids(
    vulns: list[Vulnerability], exploit_contexts: dict[str, ExploitContext]
) -> list[str]:
    """Sorted canonical ids whose exploit context says upgrade now."""
    return sorted(
        {
            v.id
            for v in vulns
            if (context := exploit_contexts.get(v.id)) is not None
            and context.priority == "upgrade_now"
        }
    )


def _unavailable_contexts(vulns: list[Vulnerability]) -> dict[str, ExploitContext]:
    """Build an all-sources-unavailable context for each vulnerability.

    Used only when `build_exploit_contexts` itself raises, which it is
    documented not to do; this is the last-resort fallback so a bug in
    enrichment never turns a successful scan into a tool failure.
    """
    contexts: dict[str, ExploitContext] = {}
    for vuln in vulns:
        cves = vuln.cve_ids()
        contexts[vuln.id] = ExploitContext(
            cves=cves,
            kev=None,
            kev_ransomware=None,
            kev_due_date=None,
            epss=None,
            epss_percentile=None,
            priority="unknown" if not cves else "check_reachability",
            sources={"kev": "unavailable: error", "epss": "unavailable: error"},
        )
    return contexts
