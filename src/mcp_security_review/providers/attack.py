"""A compact MITRE ATT&CK Enterprise technique index: build, read, refresh.

The full Enterprise STIX bundle is about 55 MB and takes seconds to parse,
so the running server never parses it on a request. Instead
`refresh_attack_index` (run by `fetch-intel`, or by the background thread
that `ensure_attack_index_background` starts) downloads the bundle once,
reduces it with `build_index` to a small JSON index, and stores that in the
intel cache under `attack-index`. Tools read the index with
`AttackIndex.load`, which accepts a stale copy: an old catalogue is better
than none, and its age is exposed so callers can ask for a refresh.

Every text field taken from the bundle (names, descriptions, platforms) is
passed through `untrusted`; technique URLs are built locally from the id.
"""

import copy
import logging
import os
import re
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import anyio
import anyio.to_thread
import httpx

from mcp_security_review.providers.intel import (
    FetchError,
    IntelCache,
    fetch_bytes,
    new_client,
    untrusted,
)

if TYPE_CHECKING:
    from mitreattack.stix20 import MitreAttackData

# `mitreattack` and `stix2` take seconds to import, so they are imported only
# where a bundle is parsed; reading the built index must stay cheap because
# every review tool does it.

logger = logging.getLogger(__name__)

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
ATTACK_INDEX_KEY = "attack-index"
ATTACK_INDEX_TTL = timedelta(days=7)
ATTACK_MAX_BYTES = 150 * 1024 * 1024
ATTACK_FETCH_DEADLINE = 600.0
"""Wall-clock seconds for the bundle download; it is far larger than a feed."""

_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_OBJECT_ID = re.compile(r"^[A-Z]{1,4}\d{4}$")  # M1050, G0016, S0154
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MARKDOWN_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_SPACES = re.compile(r"[ \t]+")

_DESCRIPTION_LIMIT = 600
_NAME_LIMIT = 200
_LIST_LIMIT = 10

PENDING_STATUS = "pending: ATT&CK catalogue downloading; ids only"

# Single-flight guard for the background refresh: held while a refresh
# thread runs, released by that thread when it ends.
_refresh_lock = threading.Lock()
_refresh_thread: threading.Thread | None = None


# ---- Build ----


def _attack_id(obj: Any) -> str | None:
    """Return the ATT&CK external id (`T1190`, `M1050`, `G0016`) of an object."""
    for ref in obj.get("external_references", None) or []:
        if ref.get("source_name") == "mitre-attack":
            ext = ref.get("external_id")
            return ext if isinstance(ext, str) else None
    return None


def _is_current(obj: Any) -> bool:
    """Say whether an object is neither revoked nor deprecated."""
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def _first_paragraph(text: object) -> str:
    """Return the first paragraph of a description without citation markup."""
    if not isinstance(text, str):
        return ""
    para = text.replace("\r\n", "\n").strip().split("\n\n", 1)[0]
    para = _CITATION.sub("", para)
    para = _MARKDOWN_LINK.sub(r"\1", para)
    para = _SPACES.sub(" ", para).strip()
    return untrusted(para, _DESCRIPTION_LIMIT)


def _technique_url(tid: str) -> str:
    """Build the attack.mitre.org page URL for a technique id."""
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/")


def _named_refs(
    entries: list[Any], *, sort_by_name: bool, limit: int = _LIST_LIMIT
) -> list[dict[str, str]]:
    """Turn relationship entries into `[{"id", "name"}]`, deduplicated."""
    seen: dict[str, str] = {}
    for entry in entries:
        obj = entry.get("object") if isinstance(entry, dict) else None
        if obj is None or not _is_current(obj):
            continue
        ext = _attack_id(obj)
        name = obj.get("name")
        if not ext or not _OBJECT_ID.fullmatch(ext) or not isinstance(name, str):
            continue
        if ext in seen:
            continue
        seen[ext] = untrusted(name, _NAME_LIMIT)
    items = [{"id": ext, "name": name} for ext, name in seen.items()]
    if sort_by_name:
        items.sort(key=lambda item: (item["name"].lower(), item["id"]))
    else:
        items.sort(key=lambda item: item["id"])
    return items[:limit]


def _detections_by_technique(data: "MitreAttackData") -> dict[str, list[str]]:
    """Map technique STIX id to the names of data components that detect it.

    ATT&CK before v18 links data components to techniques directly with
    `detects`; from v18 a detection strategy detects the technique and its
    analytics name the data components. Both shapes are read.
    """
    components = {
        dc["id"]: dc.get("name")
        for dc in data.get_datacomponents(remove_revoked_deprecated=True)
    }
    analytics = {an["id"]: an for an in data.get_objects_by_type("x-mitre-analytic")}
    names: dict[str, set[str]] = {}
    legacy = data.get_all_datacomponents_detecting_all_techniques()
    for tech_id, entries in legacy.items():
        for entry in entries:
            name = entry["object"].get("name")
            if isinstance(name, str):
                names.setdefault(tech_id, set()).add(name)
    strategies = data.get_all_detection_strategies_detecting_all_techniques()
    for tech_id, entries in strategies.items():
        for entry in entries:
            for analytic_ref in entry["object"].get("x_mitre_analytic_refs", []):
                analytic = analytics.get(analytic_ref)
                if analytic is None:
                    continue
                refs = analytic.get("x_mitre_log_source_references", []) or []
                for log_ref in refs:
                    name = components.get(log_ref.get("x_mitre_data_component_ref"))
                    if isinstance(name, str):
                        names.setdefault(tech_id, set()).add(name)
    return {
        tech_id: [untrusted(n, _NAME_LIMIT) for n in sorted(found)][:_LIST_LIMIT]
        for tech_id, found in names.items()
    }


def _bundle_version(data: "MitreAttackData") -> str:
    """Read the ATT&CK release from the bundle's collection object."""
    for collection in data.get_objects_by_type("x-mitre-collection"):
        version = collection.get("x_mitre_version")
        if isinstance(version, str) and version:
            return untrusted(version, 20)
    return "unknown"


def build_index(stix_path: Path) -> dict[str, Any]:
    """Reduce an ATT&CK Enterprise STIX bundle to a compact JSON index.

    Slow (seconds) and memory hungry for the full bundle: call it off the
    request path, as `refresh_attack_index` does.

    Args:
        stix_path: Path to an ATT&CK Enterprise STIX 2.x bundle.

    Returns:
        `{"version", "built_at", "techniques": {id: {...}}}`, where each
        technique has `id, name, tactics, platforms, description, url,
        deprecated, revoked, revoked_by, mitigations, detections, groups,
        software`. Revoked and deprecated techniques are kept and flagged.

    Raises:
        ValueError: The bundle holds no ATT&CK techniques, or is not valid
            JSON.
        STIXError: The bundle is not valid STIX.
        OSError: The file cannot be read.
    """
    from mitreattack.stix20 import MitreAttackData  # slow import, see top

    data = MitreAttackData(stix_filepath=str(stix_path))
    techniques = data.get_techniques(remove_revoked_deprecated=False)
    groups = data.get_all_groups_using_all_techniques()
    software = data.get_all_software_using_all_techniques()
    mitigations = data.get_all_mitigations_mitigating_all_techniques()
    detections = _detections_by_technique(data)
    revokers = data.get_related("attack-pattern", "revoked-by", "attack-pattern")

    out: dict[str, dict[str, Any]] = {}
    for tech in techniques:
        tid = _attack_id(tech)
        name = tech.get("name")
        if not tid or not _TECHNIQUE_ID.fullmatch(tid) or not isinstance(name, str):
            continue
        stix_id = tech["id"]
        revoked_by: str | None = None
        for entry in revokers.get(stix_id, []):
            target = _attack_id(entry["object"])
            if target and _TECHNIQUE_ID.fullmatch(target):
                revoked_by = target
                break
        tactics = [
            untrusted(phase.get("phase_name", ""), 60)
            for phase in tech.get("kill_chain_phases", None) or []
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        platforms = [
            untrusted(p, 60)
            for p in tech.get("x_mitre_platforms", None) or []
            if isinstance(p, str)
        ]
        out[tid] = {
            "id": tid,
            "name": untrusted(name, _NAME_LIMIT),
            "tactics": tactics,
            "platforms": platforms,
            "description": _first_paragraph(tech.get("description")),
            "url": _technique_url(tid),
            "deprecated": bool(tech.get("x_mitre_deprecated", False)),
            "revoked": bool(tech.get("revoked", False)),
            "revoked_by": revoked_by,
            "mitigations": _named_refs(
                mitigations.get(stix_id, []), sort_by_name=False
            ),
            "detections": detections.get(stix_id, []),
            "groups": _named_refs(groups.get(stix_id, []), sort_by_name=True),
            "software": _named_refs(software.get(stix_id, []), sort_by_name=True),
        }
    if not out:
        msg = "bundle holds no ATT&CK techniques"
        raise ValueError(msg)
    return {
        "version": _bundle_version(data),
        "built_at": datetime.now(UTC).isoformat(),
        "techniques": out,
    }


# ---- Read ----


class AttackIndex:
    """A read-only view of a built ATT&CK technique index.

    Attributes:
        version: ATT&CK release the index was built from, e.g. `"20.0"`.
        built_at: ISO 8601 time the index was built.
        fetched_at: When the index was written to the cache, or None when
            it did not come from the cache.
    """

    def __init__(
        self,
        version: str,
        techniques: dict[str, dict[str, Any]],
        *,
        built_at: str = "",
        fetched_at: datetime | None = None,
    ) -> None:
        """Wrap already-validated technique entries keyed by technique id."""
        self.version = version
        self.built_at = built_at
        self.fetched_at = fetched_at
        self._techniques = techniques

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackIndex":
        """Build an index from the dict `build_index` returns.

        Entries without a valid technique id or a name are dropped.

        Args:
            data: `{"version": str, "techniques": {id: {...}}}`.

        Returns:
            The index.

        Raises:
            ValueError: `data` does not have that shape.
        """
        if not isinstance(data, dict):
            msg = "ATT&CK index must be an object"
            raise ValueError(msg)
        version = data.get("version")
        techniques = data.get("techniques")
        if not isinstance(version, str) or not isinstance(techniques, dict):
            msg = "ATT&CK index needs a string version and a techniques map"
            raise ValueError(msg)
        built_at = data.get("built_at")
        cleaned: dict[str, dict[str, Any]] = {}
        for tid, tech in techniques.items():
            if not isinstance(tid, str) or not _TECHNIQUE_ID.fullmatch(tid):
                continue
            if not isinstance(tech, dict) or tech.get("id") != tid:
                continue
            if not isinstance(tech.get("name"), str):
                continue
            cleaned[tid] = tech
        return cls(
            version,
            cleaned,
            built_at=built_at if isinstance(built_at, str) else "",
        )

    @classmethod
    def load(cls, cache: IntelCache | None = None) -> "AttackIndex | None":
        """Read the index from the cache, accepting a stale copy.

        Args:
            cache: Cache to read. A default `IntelCache()` when omitted.

        Returns:
            The index, or None when it is absent or corrupt. Check
            `is_stale` to decide whether to start a refresh.
        """
        active = cache if cache is not None else IntelCache()
        entry = active.get_stale(ATTACK_INDEX_KEY)
        if entry is None:
            return None
        data, fetched_at = entry
        try:
            index = cls.from_dict(data)
        except ValueError:
            logger.warning("Ignoring malformed cached ATT&CK index")
            return None
        index.fetched_at = fetched_at
        return index

    @property
    def age(self) -> timedelta | None:
        """Time since the index was cached, or None if unknown."""
        if self.fetched_at is None:
            return None
        return datetime.now(UTC) - self.fetched_at

    @property
    def is_stale(self) -> bool:
        """Whether the cached index is older than `ATTACK_INDEX_TTL`."""
        age = self.age
        return age is not None and age >= ATTACK_INDEX_TTL

    def technique(self, tid: str) -> dict[str, Any] | None:
        """Return one technique by id (case-insensitive), or None.

        Args:
            tid: Technique id such as `T1190` or `T1078.004`.

        Returns:
            A copy of the technique entry, or None if unknown.
        """
        tech = self._techniques.get(tid.strip().upper())
        return copy.deepcopy(tech) if tech is not None else None

    def search(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """Find techniques by id or by words in their name or description.

        Exact id matches rank first, then id prefixes (a parent's
        sub-techniques), then name matches, then description matches.
        Revoked and deprecated techniques rank below current ones.

        Args:
            query: Free text or a technique id; case-insensitive.
            limit: Maximum number of results.

        Returns:
            Copies of the matching technique entries, best first.
        """
        needle = " ".join(query.lower().split())
        if not needle or limit <= 0:
            return []
        words = needle.split()
        scored: list[tuple[int, str, dict[str, Any]]] = []
        for tid, tech in self._techniques.items():
            low_id = tid.lower()
            name = str(tech.get("name", "")).lower()
            desc = str(tech.get("description", "")).lower()
            if needle == low_id:
                score = 100
            elif low_id.startswith(needle + ".") or (
                len(needle) >= 2 and low_id.startswith(needle)
            ):
                score = 90
            elif needle == name:
                score = 80
            elif needle in name:
                score = 65 if name.startswith(needle) else 60
            elif all(word in name for word in words):
                score = 40
            elif needle in desc:
                score = 20
            elif all(word in name or word in desc for word in words):
                score = 10
            else:
                continue
            if tech.get("revoked") or tech.get("deprecated"):
                score -= 50
            scored.append((score, tid, tech))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [copy.deepcopy(tech) for _score, _tid, tech in scored[:limit]]


def attack_summary(
    tids: list[str], index: AttackIndex | None
) -> tuple[list[dict[str, Any]], str]:
    """Summarise technique ids for a review, with a source status.

    Args:
        tids: Technique ids; duplicates are dropped, order is kept.
        index: A loaded index, or None while the catalogue downloads.

    Returns:
        `(items, status)`. Each item is
        `{"id", "name", "tactics", "revoked", "revoked_by"}`, or just
        `{"id"}` when there is no index or the id is unknown. `status` is
        `"ok (ATT&CK <version>)"` or `PENDING_STATUS`.
    """
    unique = list(dict.fromkeys(tids))
    if index is None:
        return [{"id": tid} for tid in unique], PENDING_STATUS
    items: list[dict[str, Any]] = []
    for tid in unique:
        tech = index.technique(tid)
        if tech is None:
            items.append({"id": tid})
            continue
        items.append(
            {
                "id": tech["id"],
                "name": tech.get("name"),
                "tactics": tech.get("tactics", []),
                "revoked": bool(tech.get("revoked", False)),
                "revoked_by": tech.get("revoked_by"),
            }
        )
    return items, f"ok (ATT&CK {index.version})"


# ---- Refresh ----


def _write_temp(root: Path, body: bytes) -> Path:
    """Write the bundle to a private temp file under the cache root."""
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    fd, name = tempfile.mkstemp(dir=root, prefix=".attack-stix.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(body)
    except OSError:
        Path(name).unlink(missing_ok=True)
        raise
    return Path(name)


async def refresh_attack_index(
    client: httpx.AsyncClient, cache: IntelCache
) -> dict[str, Any]:
    """Download the Enterprise bundle, build the index, and cache it.

    The bundle goes to a temp file under the cache root that is deleted
    afterwards; parsing runs in a worker thread.

    Args:
        client: Client from `new_client`.
        cache: Cache the index is written to under `attack-index`.

    Returns:
        The built index.

    Raises:
        FetchError: The download failed (see `FetchError` codes), the
            bundle could not be parsed (`invalid_stix`), or the temp file
            could not be written (`cache_error`).
    """
    from stix2.exceptions import STIXError  # slow import, see top

    resp = await fetch_bytes(
        client,
        ATTACK_STIX_URL,
        max_bytes=ATTACK_MAX_BYTES,
        deadline=ATTACK_FETCH_DEADLINE,
    )
    body = resp.content
    del resp
    try:
        path = await anyio.to_thread.run_sync(_write_temp, cache.root, body)
    except OSError as exc:
        raise FetchError("cache_error", "cannot write ATT&CK bundle") from exc
    del body
    try:
        index = await anyio.to_thread.run_sync(build_index, path)
    except (ValueError, TypeError, KeyError, RecursionError, STIXError) as exc:
        raise FetchError("invalid_stix", type(exc).__name__) from exc
    finally:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Could not remove %s: %s", path, exc)
    cache.put(ATTACK_INDEX_KEY, index)
    return index


async def _refresh_with_own_client(cache: IntelCache) -> None:
    """Run one refresh with a client owned by this call."""
    async with new_client() as client:
        await refresh_attack_index(client, cache)


def _refresh_worker(cache: IntelCache) -> None:
    """Thread body: run a refresh on a private event loop, never raising."""
    try:
        anyio.run(_refresh_with_own_client, cache)
        logger.info("ATT&CK index refreshed")
    except FetchError as exc:
        logger.warning("ATT&CK index refresh failed: %s", exc.code)
    except Exception:  # defensive: a background thread must never raise
        logger.exception("ATT&CK index refresh failed")
    finally:
        _refresh_lock.release()


def ensure_attack_index_background(cache: IntelCache | None = None) -> bool:
    """Start a background refresh of the ATT&CK index if it is not fresh.

    At most one refresh runs per process: the thread is a daemon with its
    own event loop, so the caller's request is never blocked.

    Args:
        cache: Cache to check and fill. A default `IntelCache()` if omitted.

    Returns:
        True if a refresh thread was started; False if the index is fresh,
        a refresh is already running, or the check itself failed. Never
        raises.
    """
    global _refresh_thread
    try:
        active = cache if cache is not None else IntelCache()
        if active.get(ATTACK_INDEX_KEY, ATTACK_INDEX_TTL) is not None:
            return False
        if not _refresh_lock.acquire(blocking=False):
            return False
        thread = threading.Thread(
            target=_refresh_worker,
            args=(active,),
            name="attack-index-refresh",
            daemon=True,
        )
        _refresh_thread = thread
        try:
            thread.start()
        except RuntimeError:
            _refresh_lock.release()
            raise
        return True
    except Exception:  # defensive: callers rely on this never raising
        logger.exception("Could not start ATT&CK index refresh")
        return False
