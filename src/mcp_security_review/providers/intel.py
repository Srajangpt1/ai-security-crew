"""Threat intelligence from public sources, fetched safely and cached.

This module is the network boundary for enrichment lookups. Everything that
leaves the process goes through `fetch_bytes`, which refuses plain HTTP,
never follows redirects on its own, re-checks each hop, and stops reading a
body once it passes a byte cap. Hosts that come from user input (registry
names, token realms) are checked with `check_public_host` so a request can
never be steered at loopback, private, link-local, or metadata addresses.

Responses are cached as plain JSON files, and any text taken from a feed is
passed through `untrusted` before it is returned to an agent.
"""

import ipaddress
import json
import logging
import os
import re
import socket
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import quote, urlencode

import anyio
import httpx

from mcp_security_review.guard.clip import clip

if TYPE_CHECKING:
    from mcp_security_review.providers.attack import AttackIndex

logger = logging.getLogger(__name__)


class _CveBearing(Protocol):
    """Anything shaped like a `Vulnerability`: an id plus CVE ids.

    Used instead of importing `Vulnerability` at runtime, which would make
    `providers/sca/osv.py` and this module import each other.
    """

    id: str

    def cve_ids(self) -> list[str]: ...


# ---- HTTP ----

MAX_REDIRECTS = 3
MAX_FETCH_SECONDS = 60.0
"""Wall-clock cap for one fetch, redirects included, so a slow drip ends."""

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_DROPPED_BODY_HEADERS = ("content-encoding", "content-length", "transfer-encoding")


class FetchError(Exception):
    """A fetch failed; `code` says why in a short machine-readable form.

    Codes: `timeout`, `connect_failed`, `http_<status>`, `rate_limited`,
    `response_too_large`, `invalid_json`, `unsafe_host`, `too_many_redirects`.
    For `http_<status>` and `rate_limited`, `headers` holds the response
    headers (an OCI registry's 401 carries its token challenge there).
    """

    def __init__(
        self, code: str, message: str = "", headers: httpx.Headers | None = None
    ) -> None:
        """Store the failure code, an optional message, and response headers."""
        super().__init__(message or code)
        self.code = code
        self.headers = headers if headers is not None else httpx.Headers()


def new_client(timeout: float = 15.0) -> httpx.AsyncClient:
    """Build an HTTP client with safe defaults for intel lookups.

    Args:
        timeout: Read, write, and pool timeout in seconds. Connect is 5s.

    Returns:
        An `httpx.AsyncClient` with TLS verification on and redirects off.
    """
    # Imported here: the package __init__ pulls in the CLI and server modules.
    from mcp_security_review import __version__

    return httpx.AsyncClient(
        verify=True,
        follow_redirects=False,
        timeout=httpx.Timeout(timeout, connect=5.0),
        headers={
            "User-Agent": f"mcp-security-review/{__version__}",
            # No compression: a small gzip body can inflate far past max_bytes
            # before the cap sees it, so ask for the raw size up front.
            "Accept-Encoding": "identity",
        },
    )


async def _check_url(url: httpx.URL, *, guard_host: bool) -> None:
    """Refuse non-HTTPS URLs and, when guarding, non-public hosts."""
    if url.scheme != "https":
        raise FetchError("unsafe_host", f"only https is allowed, got {url.scheme!r}")
    if not guard_host:
        return
    if url.userinfo:
        raise FetchError("unsafe_host", "credentials in URL are not allowed")
    if url.port not in (None, 443):
        raise FetchError("unsafe_host", f"port {url.port} is not allowed")
    await _guard_host(url.host)


async def _guard_host(host: str) -> None:
    """Run `check_public_host`, reporting a refusal as `unsafe_host`."""
    try:
        await check_public_host(host)
    except UnsafeHostError as exc:
        raise FetchError("unsafe_host", str(exc)) from exc


async def _read_capped(resp: httpx.Response, max_bytes: int) -> bytes:
    """Read a streamed body, stopping as soon as it exceeds `max_bytes`."""
    declared = resp.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > max_bytes:
        raise FetchError("response_too_large", f"declared {declared} bytes")
    body = bytearray()
    async for chunk in resp.aiter_bytes():
        body.extend(chunk)
        if len(body) > max_bytes:
            raise FetchError("response_too_large", f"over {max_bytes} bytes")
    return bytes(body)


async def _fetch(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int,
    headers: dict[str, str] | None,
    method: str,
    guard_host: bool,
) -> httpx.Response:
    """Do the request loop for `fetch_bytes`, without the overall deadline."""
    current = httpx.URL(url)
    send_headers = dict(headers or {})
    for hop in range(MAX_REDIRECTS + 1):
        await _check_url(current, guard_host=guard_host)
        request = client.build_request(method, current, headers=send_headers)
        resp = await client.send(request, stream=True)
        try:
            if resp.status_code in _REDIRECT_STATUSES:
                location = resp.headers.get("location")
                if not location:
                    code = f"http_{resp.status_code}"
                    raise FetchError(code, "redirect without location")
                if hop == MAX_REDIRECTS:
                    raise FetchError("too_many_redirects", f"more than {MAX_REDIRECTS}")
                target = current.join(location)
                if target.host != current.host and not guard_host:
                    # Even fixed feeds must not bounce us onto an internal host.
                    await _guard_host(target.host)
                if (target.host, target.port) != (current.host, current.port):
                    # Never hand credentials to an origin the caller did not name.
                    send_headers = {
                        k: v
                        for k, v in send_headers.items()
                        if k.lower() not in ("authorization", "cookie")
                    }
                if resp.status_code == 303:
                    method = "GET"
                current = target
                continue
            if resp.status_code == 429:
                raise FetchError(
                    "rate_limited", "upstream returned 429", headers=resp.headers
                )
            if resp.status_code >= 400:
                code = f"http_{resp.status_code}"
                raise FetchError(code, headers=resp.headers)
            body = await _read_capped(resp, max_bytes)
        finally:
            await resp.aclose()
        kept = [
            (k, v)
            for k, v in resp.headers.multi_items()
            if k.lower() not in _DROPPED_BODY_HEADERS
        ]
        return httpx.Response(
            resp.status_code, headers=kept, content=body, request=request
        )
    raise FetchError("too_many_redirects", f"more than {MAX_REDIRECTS}")


async def fetch_bytes(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    guard_host: bool = False,
    deadline: float | None = None,
) -> httpx.Response:
    """Fetch an HTTPS URL with a byte cap and manual, re-checked redirects.

    Args:
        client: Client from `new_client` (or a test client).
        url: HTTPS URL to fetch.
        max_bytes: Largest decoded body accepted.
        headers: Extra request headers. Authorization and Cookie are dropped
            when a redirect moves to a different host.
        method: HTTP method.
        guard_host: Check every hop with `check_public_host` and refuse
            credentials in the URL or a port other than 443. Use it whenever
            the host comes from user or upstream input. Without it, a
            redirect to a different host is still checked.
        deadline: Wall-clock seconds for the whole fetch, redirects
            included. Defaults to `MAX_FETCH_SECONDS`; raise it only for a
            large fixed feed.

    Returns:
        A fully read response whose `content` is the decoded body.

    Raises:
        FetchError: On any failure; see the class for codes.
    """
    limit = MAX_FETCH_SECONDS if deadline is None else deadline
    try:
        with anyio.fail_after(limit):
            return await _fetch(
                client,
                url,
                max_bytes=max_bytes,
                headers=headers,
                method=method,
                guard_host=guard_host,
            )
    except TimeoutError as exc:
        raise FetchError("timeout", f"no full response in {limit}s") from exc
    except httpx.TimeoutException as exc:
        raise FetchError("timeout", type(exc).__name__) from exc
    except httpx.TransportError as exc:
        raise FetchError("connect_failed", type(exc).__name__) from exc
    except httpx.InvalidURL as exc:
        raise FetchError("unsafe_host", "invalid URL") from exc
    except httpx.HTTPError as exc:  # e.g. DecodingError on a corrupt gzip body
        raise FetchError("connect_failed", type(exc).__name__) from exc


async def fetch_json(
    client: httpx.AsyncClient, url: str, *, max_bytes: int, **kw: Any
) -> Any:
    """Fetch a URL with `fetch_bytes` and parse the body as JSON.

    Args:
        client: Client from `new_client`.
        url: HTTPS URL to fetch.
        max_bytes: Largest body accepted.
        **kw: Passed through to `fetch_bytes`.

    Returns:
        The parsed JSON value.

    Raises:
        FetchError: As `fetch_bytes`, or `invalid_json` if parsing fails.
    """
    resp = await fetch_bytes(client, url, max_bytes=max_bytes, **kw)
    try:
        return json.loads(resp.content)
    # ValueError covers JSONDecodeError and UnicodeDecodeError; deeply nested
    # input makes the parser raise RecursionError instead.
    except (ValueError, RecursionError) as exc:
        raise FetchError("invalid_json", "response is not valid JSON") from exc


# ---- Host guard ----

HOSTNAME_RE = r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
_HOSTNAME = re.compile(HOSTNAME_RE)
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")
# Names that only resolve inside a private network (cloud metadata lives here).
_PRIVATE_SUFFIXES = (
    ".internal",
    ".local",
    ".localhost",
    ".localdomain",
    ".home.arpa",
    ".arpa",
    ".lan",
)


class UnsafeHostError(ValueError):
    """A host is not a public DNS name, or resolves to a non-public address."""


class UnresolvableHostError(UnsafeHostError):
    """A well-formed public-looking name that has no DNS addresses."""


def _blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Say whether an address must never be contacted."""
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.ipv4_mapped or ip.sixtofour
        if embedded is not None and _blocked(embedded):
            return True
    if isinstance(ip, ipaddress.IPv4Address) and ip in _SHARED_ADDRESS_SPACE:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    )


async def check_public_host(host: str) -> None:
    """Refuse a host unless it is a public DNS name with only public addresses.

    Args:
        host: A bare hostname: no scheme, port, user info, or brackets.

    Raises:
        UnsafeHostError: The name is malformed, is an IP literal, has a
            private-network suffix, or any address it resolves to is
            private, loopback, link-local, multicast, reserved,
            unspecified, or in 100.64.0.0/10.
        UnresolvableHostError: The name does not resolve (a subclass of
            `UnsafeHostError`, so callers that only refuse still refuse).
    """
    if not host.isascii():
        msg = f"not a valid public hostname: {host[:100]!r}"
        raise UnsafeHostError(msg)
    name = host.lower()
    try:
        ipaddress.ip_address(name.strip("[]"))
    except ValueError:
        pass
    else:
        msg = f"IP literal hosts are not allowed: {host!r}"
        raise UnsafeHostError(msg)
    if not _HOSTNAME.fullmatch(name):
        msg = f"not a valid public hostname: {host[:100]!r}"
        raise UnsafeHostError(msg)
    if name.endswith(_PRIVATE_SUFFIXES):
        msg = f"private-network name: {host!r}"
        raise UnsafeHostError(msg)
    try:
        infos = await anyio.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        msg = f"cannot resolve {host!r}"
        raise UnresolvableHostError(msg) from exc
    if not infos:
        msg = f"no addresses for {host!r}"
        raise UnresolvableHostError(msg)
    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError as exc:
            msg = f"{host!r} resolved to {addr!r}"
            raise UnsafeHostError(msg) from exc
        if _blocked(ip):
            msg = f"{host!r} resolves to non-public address {ip}"
            raise UnsafeHostError(msg)


# ---- Cache ----

_CACHE_KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,80}$")


def _default_cache_root() -> Path:
    """Pick the cache directory from the environment."""
    explicit = os.environ.get("MCP_SECURITY_REVIEW_CACHE_DIR")
    if explicit:
        return Path(explicit)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "mcp-security-review"
    return Path.home() / ".cache" / "mcp-security-review"


class IntelCache:
    """A small on-disk cache of JSON values with fetch timestamps.

    Each key is stored as `<root>/<key>.json` holding
    `{"fetched_at": <ISO 8601 UTC>, "data": <value>}`. Files are written
    atomically, the directory is private (0o700), and anything unreadable,
    malformed, or dated in the future is treated as a miss.
    """

    def __init__(self, root: Path | None = None) -> None:
        """Use `root`, or the directory named by the environment.

        Args:
            root: Cache directory. Defaults to `$MCP_SECURITY_REVIEW_CACHE_DIR`,
                then `$XDG_CACHE_HOME/mcp-security-review`, then
                `~/.cache/mcp-security-review`.
        """
        self.root: Path = root if root is not None else _default_cache_root()

    def _path(self, key: str) -> Path:
        if not _CACHE_KEY.fullmatch(key):
            msg = f"invalid cache key: {key[:100]!r}"
            raise ValueError(msg)
        return self.root / f"{key}.json"

    def _load(self, key: str) -> tuple[Any, datetime] | None:
        path = self._path(key)
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError):
            return None
        if not isinstance(entry, dict) or "data" not in entry:
            return None
        stamp = entry.get("fetched_at")
        if not isinstance(stamp, str):
            return None
        try:
            fetched_at = datetime.fromisoformat(stamp)
        except ValueError:
            return None
        if fetched_at.tzinfo is None or fetched_at > datetime.now(UTC):
            return None
        return entry["data"], fetched_at

    def get(self, key: str, ttl: timedelta) -> Any | None:
        """Return the cached value if it is younger than `ttl`, else None.

        Args:
            key: Cache key matching `^[a-z0-9][a-z0-9._-]{0,80}$`.
            ttl: Maximum age of a usable entry.

        Raises:
            ValueError: The key is malformed.
        """
        loaded = self._load(key)
        if loaded is None:
            return None
        data, fetched_at = loaded
        if datetime.now(UTC) - fetched_at >= ttl:
            return None
        return data

    def get_stale(self, key: str) -> tuple[Any, datetime] | None:
        """Return the cached value and its fetch time regardless of age.

        Use this as a fallback when a refresh fails.

        Raises:
            ValueError: The key is malformed.
        """
        return self._load(key)

    def put(self, key: str, value: Any) -> None:
        """Store a JSON-serialisable value under `key`, stamped with now.

        Disk errors are logged and ignored: the cache is best effort.

        Raises:
            ValueError: The key is malformed.
            TypeError: The value cannot be serialised as JSON.
        """
        path = self._path(key)
        payload = json.dumps(
            {"fetched_at": datetime.now(UTC).isoformat(), "data": value}
        )
        tmp_name: str | None = None
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.root, 0o700)
            fd, tmp_name = tempfile.mkstemp(
                dir=self.root, prefix=f".{key}.", suffix=".tmp"
            )
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp_name, path)
            tmp_name = None
        except OSError as exc:
            logger.warning("Could not write intel cache %s: %s", path, exc)
        finally:
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass


# ---- Untrusted text ----

_UNSAFE_CHARS = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"  # C0 (minus tab, LF, CR), DEL, C1
    r"\u061c\u200b-\u200f\ufeff"  # ALM, zero-width, LRM/RLM, BOM
    r"\u202a-\u202e\u2066-\u2069"  # bidi embeddings, overrides, isolates
    r"\U000e0000-\U000e007f]"  # Unicode tag characters
)


def untrusted(text: object, limit: int) -> str:
    """Make third-party text safe to hand back as data.

    Removes C0 and C1 control characters (keeping tab, newline, and carriage
    return), bidirectional controls, zero-width and byte-order marks, and
    Unicode tag characters, then clips to `limit` characters.

    Args:
        text: Any value; it is converted with `str`.
        limit: Characters to keep, not counting the omitted marker.

    Returns:
        The cleaned, clipped text.
    """
    return clip(_UNSAFE_CHARS.sub("", str(text)), limit)


# ---- KEV ----

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_KEV_CACHE_KEY = "kev"
_KEV_TTL = timedelta(hours=24)
_KEV_MAX_BYTES = 20 * 1024 * 1024


@dataclass
class KevEntry:
    """One CISA Known Exploited Vulnerabilities catalog entry.

    Attributes:
        cve: The CVE id this entry is for.
        ransomware: Whether CISA has recorded ransomware campaign use.
        due_date: Remediation due date (`YYYY-MM-DD`), if the feed has one.
        date_added: Date the entry was added to the catalog, if present.
    """

    cve: str
    ransomware: bool
    due_date: str | None
    date_added: str | None


def _parse_kev(data: Any) -> dict[str, KevEntry]:
    """Turn a raw KEV feed payload into a map keyed by CVE id."""
    out: dict[str, KevEntry] = {}
    if not isinstance(data, dict):
        return out
    entries = data.get("vulnerabilities", [])
    if not isinstance(entries, list):
        return out
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("cveID")
        if not isinstance(cve, str) or not cve:
            continue
        due_date = entry.get("dueDate")
        date_added = entry.get("dateAdded")
        out[cve] = KevEntry(
            cve=cve,
            ransomware=str(entry.get("knownRansomwareCampaignUse", "")).strip().lower()
            == "known",
            due_date=due_date if isinstance(due_date, str) else None,
            date_added=date_added if isinstance(date_added, str) else None,
        )
    return out


async def load_kev(
    client: httpx.AsyncClient, cache: IntelCache, *, refresh: bool = False
) -> dict[str, KevEntry]:
    """Load the CISA KEV catalog, caching it on disk for 24 hours.

    Args:
        client: Client from `new_client`.
        cache: Cache to read from and write to.
        refresh: Skip the fresh-cache check and fetch unconditionally. A
            failed fetch still falls back to a stale cached copy.

    Returns:
        KEV entries keyed by CVE id.

    Raises:
        FetchError: The fetch failed and no cached copy, stale or fresh,
            is available.
    """
    if not refresh:
        cached = cache.get(_KEV_CACHE_KEY, _KEV_TTL)
        if cached is not None:
            return _parse_kev(cached)
    try:
        data = await fetch_json(client, KEV_URL, max_bytes=_KEV_MAX_BYTES)
    except FetchError:
        stale = cache.get_stale(_KEV_CACHE_KEY)
        if stale is not None:
            stale_data, _fetched_at = stale
            return _parse_kev(stale_data)
        raise
    cache.put(_KEV_CACHE_KEY, data)
    return _parse_kev(data)


# ---- EPSS ----

EPSS_URL = "https://api.first.org/data/v1/epss"
_EPSS_TTL = timedelta(hours=24)
_EPSS_MAX_BYTES = 2 * 1024 * 1024
_EPSS_CHUNK_SIZE = 100

# Module-level, process-wide cache: EPSS is queried per CVE id across many
# tool calls, and a disk round trip is unnecessary for a 24 hour score.
_EPSS_CACHE: dict[str, tuple["EpssScore", datetime]] = {}


@dataclass
class EpssScore:
    """One FIRST.org EPSS score for a CVE.

    Attributes:
        cve: The CVE id this score is for.
        epss: Exploit Prediction Scoring System probability, 0.0-1.0.
        percentile: Percentile of this score among all scored CVEs, 0.0-1.0.
        date: The score's publication date as reported by the feed.
    """

    cve: str
    epss: float
    percentile: float
    date: str


def _parse_epss_items(data: Any) -> list["EpssScore"]:
    """Parse the `data` array of an EPSS API response into scores."""
    items = data.get("data", []) if isinstance(data, dict) else []
    if not isinstance(items, list):
        return []
    scores: list[EpssScore] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve")
        if not isinstance(cve, str) or not cve:
            continue
        try:
            epss_value = float(item.get("epss"))
            percentile_value = float(item.get("percentile"))
        except (TypeError, ValueError):
            continue
        date_value = item.get("date")
        scores.append(
            EpssScore(
                cve=cve,
                epss=epss_value,
                percentile=percentile_value,
                date=date_value if isinstance(date_value, str) else "",
            )
        )
    return scores


async def fetch_epss(
    client: httpx.AsyncClient, cve_ids: list[str]
) -> dict[str, EpssScore]:
    """Fetch EPSS scores for CVE ids, chunked and cached in-process.

    Args:
        client: Client from `new_client`.
        cve_ids: CVE ids to score. Duplicates are fetched once.

    Returns:
        EPSS scores keyed by CVE id. Ids the feed has no score for are
        simply absent from the result.

    Raises:
        FetchError: A chunk request failed. Scores already resolved from
            the in-memory cache before the failing chunk are lost; callers
            that want best-effort behaviour across a mix of cached and
            uncached ids should catch this themselves.
    """
    now = datetime.now(UTC)
    result: dict[str, EpssScore] = {}
    to_fetch: list[str] = []
    seen: set[str] = set()
    for cve in cve_ids:
        if cve in seen:
            continue
        seen.add(cve)
        cached = _EPSS_CACHE.get(cve)
        if cached is not None and now - cached[1] < _EPSS_TTL:
            result[cve] = cached[0]
        else:
            to_fetch.append(cve)

    for start in range(0, len(to_fetch), _EPSS_CHUNK_SIZE):
        chunk = to_fetch[start : start + _EPSS_CHUNK_SIZE]
        query = urlencode({"cve": ",".join(chunk)})
        data = await fetch_json(
            client, f"{EPSS_URL}?{query}", max_bytes=_EPSS_MAX_BYTES
        )
        for score in _parse_epss_items(data):
            result[score.cve] = score
            _EPSS_CACHE[score.cve] = (score, now)

    return result


# ---- CTID ----

CTID_TREE_API = (
    "https://api.github.com/repos/center-for-threat-informed-defense/"
    "mappings-explorer/contents/mappings/kev"
)
CTID_RAW = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
    "mappings-explorer/main/mappings/kev"
)
_CTID_CACHE_KEY = "ctid"
_CTID_TTL = timedelta(days=7)
_CTID_LISTING_MAX_BYTES = 1 * 1024 * 1024
_CTID_MAPPING_MAX_BYTES = 10 * 1024 * 1024

_ATTACK_VERSION_RE = re.compile(r"^attack-(\d+)\.(\d+)$")
_KEV_SNAPSHOT_RE = re.compile(r"^kev-(\d{2})\.(\d{2})\.(\d{4})$")
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass
class CtidMapping:
    """A CTID KEV -> ATT&CK mapping snapshot.

    Attributes:
        attack_version: The ATT&CK version directory this came from, e.g.
            `"attack-16.1"`.
        snapshot: The KEV snapshot directory this came from, e.g.
            `"kev-07.28.2025"`.
        by_cve: ATT&CK technique ids (validated `^T\\d{4}(\\.\\d{3})?$`)
            keyed by CVE id.
    """

    attack_version: str
    snapshot: str
    by_cve: dict[str, list[str]]


def _newest_dir_name(entries: Any, pattern: re.Pattern[str], key: Any) -> str | None:
    """Return the dir name matching `pattern` whose sort `key` is largest."""
    if not isinstance(entries, list):
        return None
    best_key: Any = None
    best_name: str | None = None
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("type") != "dir":
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        match = pattern.fullmatch(name)
        if not match:
            continue
        candidate_key = key(match)
        if best_key is None or candidate_key > best_key:
            best_key = candidate_key
            best_name = name
    return best_name


def _newest_attack_version(entries: Any) -> str | None:
    """Pick the highest `attack-X.Y` directory name, sorted numerically."""
    return _newest_dir_name(
        entries,
        _ATTACK_VERSION_RE,
        lambda m: (int(m.group(1)), int(m.group(2))),
    )


def _newest_kev_snapshot(entries: Any) -> str | None:
    """Pick the most recent `kev-MM.DD.YYYY` directory name, sorted by date."""
    return _newest_dir_name(
        entries,
        _KEV_SNAPSHOT_RE,
        lambda m: (int(m.group(3)), int(m.group(1)), int(m.group(2))),
    )


def _parse_ctid_mapping(
    data: Any, *, attack_version: str, snapshot: str
) -> CtidMapping:
    """Build a `CtidMapping` from a raw CTID mapping file payload."""
    by_cve: dict[str, list[str]] = {}
    objects = data.get("mapping_objects") if isinstance(data, dict) else None
    if isinstance(objects, list):
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            cve = obj.get("capability_id")
            technique = obj.get("attack_object_id")
            if not isinstance(cve, str) or not cve:
                continue
            if not isinstance(technique, str):
                continue
            if not _TECHNIQUE_ID_RE.fullmatch(technique):
                continue
            techniques = by_cve.setdefault(cve, [])
            if technique not in techniques:
                techniques.append(technique)
    return CtidMapping(attack_version=attack_version, snapshot=snapshot, by_cve=by_cve)


async def _discover_ctid(client: httpx.AsyncClient) -> CtidMapping:
    """Discover the newest CTID KEV mapping snapshot and fetch it.

    Makes two GitHub contents-API calls (the `kev` directory, then the
    newest `attack-X.Y` directory inside it) plus one raw-content fetch for
    the mapping file itself, whose name is constructed from the discovered
    version and snapshot rather than listed.

    Raises:
        FetchError: A request failed, or no usable `attack-X.Y` or
            `kev-MM.DD.YYYY` directory was found.
    """
    versions = await fetch_json(
        client, CTID_TREE_API, max_bytes=_CTID_LISTING_MAX_BYTES
    )
    version = _newest_attack_version(versions)
    if version is None:
        raise FetchError("invalid_response", "no attack-X.Y directories found")

    snapshots = await fetch_json(
        client, f"{CTID_TREE_API}/{version}", max_bytes=_CTID_LISTING_MAX_BYTES
    )
    snapshot = _newest_kev_snapshot(snapshots)
    if snapshot is None:
        raise FetchError("invalid_response", "no kev-MM.DD.YYYY directories found")

    mapping_url = (
        f"{CTID_RAW}/{version}/{snapshot}/enterprise/"
        f"{snapshot}_{version}-enterprise.json"
    )
    data = await fetch_json(client, mapping_url, max_bytes=_CTID_MAPPING_MAX_BYTES)
    return _parse_ctid_mapping(data, attack_version=version, snapshot=snapshot)


def _ctid_to_cache(mapping: CtidMapping) -> dict[str, Any]:
    """Turn a `CtidMapping` into a JSON-serialisable dict for the cache."""
    return {
        "attack_version": mapping.attack_version,
        "snapshot": mapping.snapshot,
        "by_cve": mapping.by_cve,
    }


def _ctid_from_cache(data: Any) -> CtidMapping | None:
    """Rebuild a `CtidMapping` from a cached value, or None if malformed."""
    if not isinstance(data, dict):
        return None
    version = data.get("attack_version")
    snapshot = data.get("snapshot")
    by_cve = data.get("by_cve")
    if not isinstance(version, str) or not isinstance(snapshot, str):
        return None
    if not isinstance(by_cve, dict):
        return None
    cleaned: dict[str, list[str]] = {}
    for cve, techniques in by_cve.items():
        if isinstance(cve, str) and isinstance(techniques, list):
            cleaned[cve] = [t for t in techniques if isinstance(t, str)]
    return CtidMapping(attack_version=version, snapshot=snapshot, by_cve=cleaned)


async def load_ctid(
    client: httpx.AsyncClient, cache: IntelCache, *, refresh: bool = False
) -> CtidMapping:
    """Load the CTID KEV -> ATT&CK mapping, caching it on disk for 7 days.

    Args:
        client: Client from `new_client`.
        cache: Cache to read from and write to.
        refresh: Skip the fresh-cache check and fetch unconditionally. A
            failed fetch still falls back to a stale cached copy.

    Returns:
        The newest `CtidMapping` available.

    Raises:
        FetchError: The fetch failed and no cached copy, stale or fresh,
            is available.
    """
    if not refresh:
        cached = cache.get(_CTID_CACHE_KEY, _CTID_TTL)
        if cached is not None:
            parsed = _ctid_from_cache(cached)
            if parsed is not None:
                return parsed
    try:
        mapping = await _discover_ctid(client)
    except FetchError:
        stale = cache.get_stale(_CTID_CACHE_KEY)
        if stale is not None:
            stale_data, _fetched_at = stale
            parsed = _ctid_from_cache(stale_data)
            if parsed is not None:
                return parsed
        raise
    cache.put(_CTID_CACHE_KEY, _ctid_to_cache(mapping))
    return mapping


# ---- Exploit context ----

EPSS_UPGRADE_PERCENTILE = 0.9


def priority(*, kev: bool | None, pct: float | None) -> str:
    """Decide upgrade priority from KEV membership and EPSS percentile.

    Args:
        kev: Whether the CVE is in the CISA KEV catalog, or `None` if that
            could not be determined.
        pct: EPSS percentile (0.0-1.0), or `None` if unavailable.

    Returns:
        `"upgrade_now"` when `kev` is true or `pct` is at or above
        `EPSS_UPGRADE_PERCENTILE`; `"check_reachability"` otherwise. Does
        not return `"unknown"`: that only applies when a vulnerability has
        no CVE ids at all, which callers decide before reaching this.
    """
    if kev or (pct is not None and pct >= EPSS_UPGRADE_PERCENTILE):
        return "upgrade_now"
    return "check_reachability"


@dataclass
class ExploitContext:
    """Exploitation signal for one vulnerability, from public feeds.

    Attributes:
        cves: CVE ids this context covers (from `Vulnerability.cve_ids()`).
        kev: Whether any of `cves` is in the CISA KEV catalog, or `None`
            when KEV could not be checked.
        kev_ransomware: Whether CISA recorded ransomware campaign use for
            the KEV entry, or `None` when there is no KEV entry or KEV
            could not be checked.
        kev_due_date: The KEV entry's remediation due date, or `None`.
        epss: The highest EPSS probability across `cves`, or `None` when
            EPSS could not be checked or had no score for any of them.
        epss_percentile: The percentile for `epss`, or `None`.
        attack_techniques: MITRE ATT&CK techniques linked to this
            vulnerability via the CTID KEV mapping, as `attack_summary`
            items: `{"id", "name", "tactics", "revoked", "revoked_by"}` when
            the cached ATT&CK index knows the technique, else just `{"id"}`. Empty when CTID has no mapping for any of `cves`, or
            when CTID could not be checked.
        priority: `"upgrade_now"`, `"check_reachability"`, or `"unknown"`
            (no CVE ids to look up).
        sources: Per-source status for sources that failed, e.g.
            `{"kev": "unavailable: timeout"}`. A source that succeeded is
            absent from this mapping, except `"ctid"`, which is always
            present when `cves` is non-empty: `"ok (snapshot <snapshot>)"`
            on success, `"unavailable: <code>"` on failure. When CTID
            succeeded, `"attack"` says whether technique names came from
            the ATT&CK index (`"ok (ATT&CK <version>)"`), are pending while
            it downloads, or are `"unavailable: error"`.
    """

    cves: list[str]
    kev: bool | None
    kev_ransomware: bool | None
    kev_due_date: str | None
    epss: float | None
    epss_percentile: float | None
    attack_techniques: list[dict[str, Any]] = field(default_factory=list)
    priority: str = "unknown"
    sources: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return this context as a plain, JSON-serialisable dict."""
        return {
            "cves": self.cves,
            "kev": self.kev,
            "kev_ransomware": self.kev_ransomware,
            "kev_due_date": self.kev_due_date,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "attack_techniques": self.attack_techniques,
            "priority": self.priority,
            "sources": self.sources,
        }


def _load_attack_index(cache: IntelCache) -> tuple["AttackIndex | None", str]:
    """Read the cached ATT&CK index for naming techniques, never raising.

    When the index is missing or stale, a background refresh is started (it
    never blocks) so later scans get current names.

    Returns:
        `(index, status)`. The index is None when none is cached (status is
        the pending status) or reading failed (`"unavailable: error"`);
        otherwise the status is `"ok (ATT&CK <version>)"`.
    """
    try:
        # Imported lazily: attack.py imports from this module.
        from mcp_security_review.providers import attack as attack_provider

        index = attack_provider.AttackIndex.load(cache)
        if index is None or index.is_stale:
            attack_provider.ensure_attack_index_background(cache)
        _, status = attack_provider.attack_summary([], index)
        return index, status
    except Exception:  # defensive: exploit context must never raise
        logger.exception("ATT&CK index lookup failed")
        return None, "unavailable: error"


def _summarise_techniques(
    tids: list[str], index: "AttackIndex | None"
) -> list[dict[str, Any]]:
    """Describe technique ids with `attack_summary`, never raising.

    Known techniques carry `name`, `tactics`, `revoked`, and `revoked_by`, so
    an id CTID maps that ATT&CK has since revoked reaches the agent flagged.
    """
    try:
        from mcp_security_review.providers.attack import attack_summary

        items, _ = attack_summary(tids, index)
        return items
    except Exception:  # defensive: exploit context must never raise
        logger.exception("ATT&CK technique summary failed")
        return [{"id": tid} for tid in tids]


async def build_exploit_contexts(
    vulns: list[_CveBearing],
    *,
    client: httpx.AsyncClient | None = None,
    cache: IntelCache | None = None,
) -> dict[str, ExploitContext]:
    """Build exploit context for each vulnerability, keyed by its id.

    Looks up KEV membership, EPSS scores, and the CTID KEV -> ATT&CK
    mapping for every CVE id the given vulnerabilities carry, in calls
    shared across all of them, then assembles one `ExploitContext` per
    vulnerability.

    Never raises: a KEV, EPSS, or CTID failure is recorded as
    `sources["kev"]`/`sources["epss"]`/`sources["ctid"]`
    (`"unavailable: <code>"`) and the corresponding fields are left `None`
    or empty, but the function still returns a context for every
    vulnerability passed in. Technique names come from the cached ATT&CK
    index; without one the techniques keep their ids only, and a missing or
    stale index starts a background refresh for later calls.

    Args:
        vulns: Vulnerabilities to build context for. Only `.id` and
            `.cve_ids()` are used, so an OSV `Vulnerability` or anything
            shaped like one works.
        client: Client from `new_client`. A new one is created and closed
            when omitted.
        cache: Cache for the KEV catalog and the CTID mapping. A default
            `IntelCache()` is used when omitted.

    Returns:
        `ExploitContext` keyed by vulnerability id.
    """
    owns_client = client is None
    active_client = client if client is not None else new_client()
    active_cache = cache if cache is not None else IntelCache()
    try:
        all_cve_ids: list[str] = []
        seen_cves: set[str] = set()
        for vuln in vulns:
            for cve in vuln.cve_ids():
                if cve not in seen_cves:
                    seen_cves.add(cve)
                    all_cve_ids.append(cve)

        kev_map: dict[str, KevEntry] = {}
        kev_unavailable: str | None = None
        try:
            kev_map = await load_kev(active_client, active_cache)
        except FetchError as exc:
            kev_unavailable = f"unavailable: {exc.code}"
        except Exception:  # defensive: this helper must never raise
            logger.exception("KEV lookup failed")
            kev_unavailable = "unavailable: error"

        epss_map: dict[str, EpssScore] = {}
        epss_unavailable: str | None = None
        if all_cve_ids:
            try:
                epss_map = await fetch_epss(active_client, all_cve_ids)
            except FetchError as exc:
                epss_unavailable = f"unavailable: {exc.code}"
            except Exception:  # defensive: this helper must never raise
                logger.exception("EPSS lookup failed")
                epss_unavailable = "unavailable: error"

        ctid_mapping: CtidMapping | None = None
        ctid_unavailable: str | None = None
        if all_cve_ids:
            try:
                ctid_mapping = await load_ctid(active_client, active_cache)
            except FetchError as exc:
                ctid_unavailable = f"unavailable: {exc.code}"
            except Exception:  # defensive: this helper must never raise
                logger.exception("CTID lookup failed")
                ctid_unavailable = "unavailable: error"

        attack_state: tuple[AttackIndex | None, str] | None = None
        contexts: dict[str, ExploitContext] = {}
        for vuln in vulns:
            cves = vuln.cve_ids()
            sources: dict[str, str] = {}
            if kev_unavailable is not None:
                sources["kev"] = kev_unavailable
            if epss_unavailable is not None:
                sources["epss"] = epss_unavailable

            if not cves:
                contexts[vuln.id] = ExploitContext(
                    cves=[],
                    kev=None,
                    kev_ransomware=None,
                    kev_due_date=None,
                    epss=None,
                    epss_percentile=None,
                    priority="unknown",
                    sources=sources,
                )
                continue

            kev_entry: KevEntry | None = None
            if kev_unavailable is None:
                for cve in cves:
                    kev_entry = kev_map.get(cve)
                    if kev_entry is not None:
                        break

            epss_entry: EpssScore | None = None
            if epss_unavailable is None:
                for cve in cves:
                    candidate = epss_map.get(cve)
                    if candidate is not None and (
                        epss_entry is None or candidate.epss > epss_entry.epss
                    ):
                        epss_entry = candidate

            kev_flag = None if kev_unavailable is not None else kev_entry is not None
            pct = epss_entry.percentile if epss_entry is not None else None

            attack_techniques: list[dict[str, Any]] = []
            if ctid_unavailable is not None:
                sources["ctid"] = ctid_unavailable
            elif ctid_mapping is not None:
                sources["ctid"] = f"ok (snapshot {ctid_mapping.snapshot})"
                technique_ids: set[str] = set()
                for cve in cves:
                    technique_ids.update(ctid_mapping.by_cve.get(cve, []))
                if attack_state is None:
                    attack_state = _load_attack_index(active_cache)
                attack_index, sources["attack"] = attack_state
                attack_techniques = _summarise_techniques(
                    sorted(technique_ids), attack_index
                )

            contexts[vuln.id] = ExploitContext(
                cves=cves,
                kev=kev_flag,
                kev_ransomware=kev_entry.ransomware if kev_entry else None,
                kev_due_date=kev_entry.due_date if kev_entry else None,
                epss=epss_entry.epss if epss_entry else None,
                epss_percentile=pct,
                attack_techniques=attack_techniques,
                priority=priority(kev=kev_flag, pct=pct),
                sources=sources,
            )
        return contexts
    finally:
        if owns_client:
            await active_client.aclose()


# ---- Prefetch ----

PREFETCH_SOURCES = ("kev", "ctid", "attack")


async def _prefetch_one(
    cache: IntelCache,
    key: str,
    ttl: timedelta,
    force: bool,
    refresh: Callable[[], Any],
) -> str:
    """Run one prefetch source and report its status; never raises.

    Args:
        cache: Cache the source is keyed in.
        key: The source's cache key.
        ttl: The source's freshness window.
        force: Skip the freshness check and refetch unconditionally.
        refresh: Zero-argument async callable that performs the refetch.

    Returns:
        `"fresh"` when the cache already holds a within-TTL entry and
        `force` is false, `"ok"` when `refresh` completed, or
        `"failed: <code>"` when it raised.
    """
    if not force and cache.get(key, ttl) is not None:
        return "fresh"
    try:
        await refresh()
    except FetchError as exc:
        return f"failed: {exc.code}"
    except Exception:  # defensive: a prefetch source must never raise
        logger.exception("Prefetch of %s failed", key)
        return "failed: error"
    return "ok"


async def fetch_intel(
    cache: IntelCache | None = None,
    *,
    sources: tuple[str, ...] = PREFETCH_SOURCES,
    force: bool = False,
) -> dict[str, str]:
    """Refresh the cached threat-intel sources, reporting a status for each.

    Meant for a background prefetch (the `fetch-intel` CLI command, or the
    SessionStart hook that runs it) so the first real tool call does not
    pay for a cold cache. Each source is independent: a failure on one
    does not stop the others, and this never raises.

    Args:
        cache: Cache to read and write. A default `IntelCache()` when
            omitted.
        sources: Which sources to refresh: any of `"kev"`, `"ctid"`,
            `"attack"`.
        force: Refetch even when the cache already holds a within-TTL
            entry.

    Returns:
        Status per source: `"ok"` (refetched), `"fresh"` (the cache was
        already within its TTL and `force` was false), or
        `"failed: <code>"` (the `FetchError` code, or `"error"` for any
        other exception).
    """
    active_cache = cache if cache is not None else IntelCache()
    statuses: dict[str, str] = {}
    async with new_client() as client:
        # Imported lazily: attack.py imports from this module.
        from mcp_security_review.providers import attack as attack_provider

        specs: dict[str, tuple[str, timedelta, Callable[[], Any]]] = {
            "kev": (
                _KEV_CACHE_KEY,
                _KEV_TTL,
                lambda: load_kev(client, active_cache, refresh=True),
            ),
            "ctid": (
                _CTID_CACHE_KEY,
                _CTID_TTL,
                lambda: load_ctid(client, active_cache, refresh=True),
            ),
            "attack": (
                attack_provider.ATTACK_INDEX_KEY,
                attack_provider.ATTACK_INDEX_TTL,
                lambda: attack_provider.refresh_attack_index(client, active_cache),
            ),
        }
        for name in sources:
            spec = specs.get(name)
            if spec is None:
                statuses[name] = "failed: unknown_source"
                continue
            key, ttl, refresh = spec
            statuses[name] = await _prefetch_one(active_cache, key, ttl, force, refresh)
    return statuses


# ---- deps.dev and Scorecard ----

DEPSDEV = "https://api.deps.dev/v3"
SCORECARD = "https://api.securityscorecards.dev/projects"

_DEPSDEV_MAX_BYTES = 2 * 1024 * 1024
_DEPS_MAX_BYTES = 5 * 1024 * 1024
_SCORECARD_MAX_BYTES = 1 * 1024 * 1024

_MAX_DEP_LOOKUPS = 25
_DEP_LOOKUP_CONCURRENCY = 8

# Mirrors the alias sets in `providers/sca/registry.py`. Duplicated rather
# than imported: that module imports from this one, so importing it back
# here at module scope would be circular.
_PYPI_ALIASES = frozenset({"pypi", "pip", "python"})
_NPM_ALIASES = frozenset({"npm", "node", "javascript", "js"})
_ACTIONS_ALIASES = frozenset({"github-actions", "actions", "gha"})

_PERMISSIVE_LICENSES = frozenset(
    {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "0BSD",
        "Unlicense",
        "Python-2.0",
        "PSF-2.0",
        "Zlib",
        "MPL-2.0",  # file-level ("weak") copyleft; treated as permissive here
    }
)
_COPYLEFT_PREFIXES = ("GPL", "AGPL", "LGPL", "EUPL", "SSPL", "OSL")

_SOURCE_REPO_RE = re.compile(r"^github\.com/[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
_ACTION_NAME_PREFIX_RE = re.compile(r"^([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})")

_LICENSE_TEXT_LIMIT = 100
_ADVISORY_ID_LIMIT = 100
_REASON_TEXT_LIMIT = 300
_CHECK_NAME_LIMIT = 80
_DATE_LIMIT = 40
_MAX_LICENSES = 20
_MAX_ADVISORIES = 50
_MAX_WEAKEST_CHECKS = 5
_TRANSITIVE_DEPENDENCY_LIMIT = 100


@dataclass
class PackageAssessment:
    """Pre-adoption signal for one package, from deps.dev and Scorecard.

    This is not a verdict: it is a bundle of inputs (license, provenance,
    maintenance signal, dependency shape) meant to be weighed by whoever
    decides whether to adopt the package. Every source is best effort;
    see `sources`.

    Attributes:
        name: The package name, or `owner/repo[/path]` for `github-actions`.
        version: The version string, or the action's ref.
        ecosystem: The ecosystem exactly as given by the caller.
        exists: Whether deps.dev (or, for `github-actions`, the derived
            `owner/repo`) confirmed this name and version. Not a
            substitute for `sca_verify_packages`.
        deprecated: Whether the registry marks this version deprecated,
            or `None` when that could not be determined.
        deprecated_reason: The registry's deprecation message, clipped
            with `untrusted`, or `None`.
        licenses: SPDX license identifiers reported for this version.
        license_class: `"permissive"`, `"copyleft"`, or `"unknown"`.
        advisories: Advisory ids (e.g. GHSA ids) deps.dev links to this
            version.
        provenance: Whether deps.dev records SLSA provenance or an
            attestation for this version, or `None` when unknown.
        source_repo: The `github.com/{owner}/{repo}` key used for
            Scorecard, or `None` when none was found or it did not match
            the strict pattern.
        scorecard: `{"score", "date", "weakest"}` where `weakest` is up
            to 5 `{"name", "score"}` checks (excluding not-applicable `-1`
            scores), or `None` when no Scorecard data was found.
        dependencies: `{"direct", "transitive", "deprecated"}`: counts of
            direct and transitive dependency-graph nodes, and names of
            direct dependencies found to be deprecated (checked for up to
            `_MAX_DEP_LOOKUPS` direct dependencies, `_DEP_LOOKUP_CONCURRENCY`
            at a time). `None` when the dependency graph could not be
            fetched or does not apply (`github-actions`).
        adoption_notes: Exact-string flags worth raising with whoever is
            deciding whether to adopt this package; see `_adoption_notes`.
        sources: Per-source status (`"ok"`, `"not_found"`, or
            `"unavailable: <reason>"`), keyed by `"deps_dev"`,
            `"scorecard"`, and `"dependencies"`. A source absent from this
            mapping was never attempted (for example, `"scorecard"` when
            no source repository was found).
    """

    name: str
    version: str
    ecosystem: str
    exists: bool
    deprecated: bool | None
    deprecated_reason: str | None
    licenses: list[str]
    license_class: str
    advisories: list[str]
    provenance: bool | None
    source_repo: str | None
    scorecard: dict[str, Any] | None
    dependencies: dict[str, Any] | None
    adoption_notes: list[str]
    sources: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        """Serialise this assessment as a plain, JSON-serialisable dict."""
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "exists": self.exists,
            "deprecated": self.deprecated,
            "deprecated_reason": self.deprecated_reason,
            "licenses": self.licenses,
            "license_class": self.license_class,
            "advisories": self.advisories,
            "provenance": self.provenance,
            "source_repo": self.source_repo,
            "scorecard": self.scorecard,
            "dependencies": self.dependencies,
            "adoption_notes": self.adoption_notes,
            "sources": self.sources,
        }


def _normalize_assess_ecosystem(ecosystem: str) -> str | None:
    """Map an ecosystem string (and its aliases) to a canonical name.

    Returns:
        `"pypi"`, `"npm"`, or `"github-actions"`; `None` for anything
        else (including `"container"`), which callers must treat as
        unsupported rather than failing.
    """
    eco = str(ecosystem).lower().strip()
    if eco in _PYPI_ALIASES:
        return "pypi"
    if eco in _NPM_ALIASES:
        return "npm"
    if eco in _ACTIONS_ALIASES:
        return "github-actions"
    return None


def _license_class(licenses: list[str]) -> str:
    """Classify a package's licenses as permissive, copyleft, or unknown.

    Any SPDX id with a copyleft prefix (`GPL`, `AGPL`, `LGPL`, `EUPL`,
    `SSPL`, `OSL`) anywhere in `licenses` makes the whole result
    `"copyleft"`, since that is the stricter obligation to flag. `MPL-2.0`
    is file-level ("weak") copyleft but is classified permissive here.
    """
    if not licenses:
        return "unknown"
    saw_permissive = False
    for lic in licenses:
        if any(lic.startswith(prefix) for prefix in _COPYLEFT_PREFIXES):
            return "copyleft"
        if lic in _PERMISSIVE_LICENSES:
            saw_permissive = True
    return "permissive" if saw_permissive else "unknown"


def _weakest_checks(checks: Any) -> list[dict[str, Any]]:
    """Up to 5 lowest-scoring Scorecard checks, excluding `-1` (n/a).

    Each check's original numeric type (int or float) is kept; only the
    sort key is coerced to float.
    """
    scored: list[tuple[float, int | float, str]] = []
    if isinstance(checks, list):
        for check in checks:
            if not isinstance(check, dict):
                continue
            name = check.get("name")
            score = check.get("score")
            if not isinstance(name, str) or not isinstance(score, int | float):
                continue
            if isinstance(score, bool) or score < 0:
                continue
            scored.append((float(score), score, untrusted(name, _CHECK_NAME_LIMIT)))
    scored.sort(key=lambda item: item[0])
    return [
        {"name": name, "score": score}
        for _sort_key, score, name in scored[:_MAX_WEAKEST_CHECKS]
    ]


def _maintained_score_is_zero(checks: Any) -> bool:
    """Say whether the `Maintained` check (if present) scored exactly 0."""
    if not isinstance(checks, list):
        return False
    for check in checks:
        if isinstance(check, dict) and check.get("name") == "Maintained":
            return check.get("score") == 0
    return False


def _scorecard_date(value: Any) -> str | None:
    """Clip a Scorecard `date` field through `untrusted`, or None."""
    return untrusted(value, _DATE_LIMIT) if isinstance(value, str) and value else None


def _source_repo_from_related(related: Any) -> str | None:
    """Pick the `SOURCE_REPO` project key from deps.dev `relatedProjects`.

    Returns:
        The `github.com/{owner}/{repo}` key, validated with
        `_SOURCE_REPO_RE`, or `None` when there is no such relation or it
        does not match (for example a non-GitHub forge).
    """
    if not isinstance(related, list):
        return None
    for item in related:
        if not isinstance(item, dict) or item.get("relationType") != "SOURCE_REPO":
            continue
        key = item.get("projectKey")
        if not isinstance(key, dict):
            continue
        project_id = key.get("id")
        if isinstance(project_id, str) and _SOURCE_REPO_RE.fullmatch(project_id):
            return project_id
    return None


def _action_source_repo(name: str) -> str | None:
    """Derive `github.com/{owner}/{repo}` from a `uses:` action name.

    Only the first two path components are used, so `owner/repo/path`
    actions resolve to the same repository. Returns `None` when `name`
    does not start with a well-formed `owner/repo`.
    """
    match = _ACTION_NAME_PREFIX_RE.match(name)
    if match is None:
        return None
    candidate = f"github.com/{match.group(1)}/{match.group(2)}"
    return candidate if _SOURCE_REPO_RE.fullmatch(candidate) else None


async def _fetch_version_json(
    client: httpx.AsyncClient, system: str, name: str, version: str
) -> Any:
    """Fetch one deps.dev package-version record.

    Raises:
        FetchError: Including `http_404` when the name or version is
            unknown to deps.dev.
    """
    url = (
        f"{DEPSDEV}/systems/{quote(system, safe='')}/packages/"
        f"{quote(name, safe='')}/versions/{quote(version, safe='')}"
    )
    return await fetch_json(client, url, max_bytes=_DEPSDEV_MAX_BYTES)


async def _deprecated_direct_deps(
    client: httpx.AsyncClient, system: str, direct: list[tuple[str, str]]
) -> list[str]:
    """Check up to `_MAX_DEP_LOOKUPS` direct dependencies for deprecation.

    Runs `_DEP_LOOKUP_CONCURRENCY` lookups at a time. A failed lookup for
    one dependency is skipped silently; it never fails the batch.

    Args:
        direct: `(name, version)` pairs for dependency-graph nodes with
            relation `DIRECT`.

    Returns:
        Sorted names whose looked-up version is deprecated.
    """
    sample = direct[:_MAX_DEP_LOOKUPS]
    deprecated: list[str] = []
    limiter = anyio.CapacityLimiter(_DEP_LOOKUP_CONCURRENCY)
    lock = anyio.Lock()

    async def check(name: str, version: str) -> None:
        async with limiter:
            try:
                data = await _fetch_version_json(client, system, name, version)
            except FetchError:
                return
            except Exception:  # a bad dependency record must not fail the batch
                logger.exception("Dependency deprecation check failed for %s", name)
                return
        if isinstance(data, dict) and data.get("isDeprecated") is True:
            async with lock:
                deprecated.append(name)

    async with anyio.create_task_group() as tg:
        for name, version in sample:
            tg.start_soon(check, name, version)
    return sorted(deprecated)


async def _fetch_dependency_summary(
    client: httpx.AsyncClient, system: str, name: str, version: str
) -> tuple[dict[str, Any] | None, str]:
    """Fetch and summarise the dependency graph for one package version.

    Direct dependency counts come from relation `DIRECT`; transitive
    counts from relation `INDIRECT` only (direct dependencies are not
    double-counted as transitive). Deprecation is then checked for the
    direct dependencies (see `_deprecated_direct_deps`).

    Returns:
        `(summary, status)`. `summary` is
        `{"direct", "transitive", "deprecated"}`, or `None` on failure.
        `status` is `"ok"` or `"unavailable: <reason>"`.
    """
    url = (
        f"{DEPSDEV}/systems/{quote(system, safe='')}/packages/"
        f"{quote(name, safe='')}/versions/{quote(version, safe='')}:dependencies"
    )
    try:
        data = await fetch_json(client, url, max_bytes=_DEPS_MAX_BYTES)
    except FetchError as exc:
        return None, f"unavailable: {exc.code}"
    except Exception:  # a malformed dependency response must not raise
        logger.exception("Dependency graph lookup failed for %s@%s", name, version)
        return None, "unavailable: error"

    nodes = data.get("nodes") if isinstance(data, dict) else None
    direct_pairs: list[tuple[str, str]] = []
    direct_count = 0
    transitive_count = 0
    for node in nodes if isinstance(nodes, list) else []:
        if not isinstance(node, dict):
            continue
        relation = node.get("relation")
        version_key = node.get("versionKey")
        dep_name = version_key.get("name") if isinstance(version_key, dict) else None
        dep_version = (
            version_key.get("version") if isinstance(version_key, dict) else None
        )
        if relation == "DIRECT":
            direct_count += 1
            if isinstance(dep_name, str) and isinstance(dep_version, str):
                direct_pairs.append((dep_name, dep_version))
        elif relation == "INDIRECT":
            transitive_count += 1

    deprecated_names = await _deprecated_direct_deps(client, system, direct_pairs)
    summary = {
        "direct": direct_count,
        "transitive": transitive_count,
        "deprecated": deprecated_names,
    }
    return summary, "ok"


def _scorecard_from_checks(
    score: Any, date: Any, checks: Any
) -> tuple[dict[str, Any] | None, bool]:
    """Build the `scorecard` summary dict plus the `Maintained`-is-zero flag."""
    if isinstance(score, bool) or not isinstance(score, int | float):
        return None, False
    scorecard = {
        "score": score,
        "date": _scorecard_date(date),
        "weakest": _weakest_checks(checks),
    }
    return scorecard, _maintained_score_is_zero(checks)


async def _fetch_deps_dev_scorecard(
    client: httpx.AsyncClient, source_repo: str
) -> tuple[dict[str, Any] | None, str, bool]:
    """Fetch the Scorecard embedded in deps.dev's project info.

    Returns:
        `(scorecard, status, maintained_is_zero)`.
    """
    url = f"{DEPSDEV}/projects/{quote(source_repo, safe='')}"
    try:
        data = await fetch_json(client, url, max_bytes=_DEPSDEV_MAX_BYTES)
    except FetchError as exc:
        if exc.code == "http_404":
            return None, "not_found", False
        return None, f"unavailable: {exc.code}", False
    except Exception:  # a malformed project response must not raise
        logger.exception("deps.dev project lookup failed for %s", source_repo)
        return None, "unavailable: error", False
    sc = data.get("scorecard") if isinstance(data, dict) else None
    if not isinstance(sc, dict):
        return None, "ok", False
    scorecard, maintained_zero = _scorecard_from_checks(
        sc.get("overallScore"), sc.get("date"), sc.get("checks")
    )
    return scorecard, "ok", maintained_zero


async def _fetch_scorecard_api(
    client: httpx.AsyncClient, source_repo: str
) -> tuple[dict[str, Any] | None, str, bool]:
    """Fetch a project's Scorecard directly from api.securityscorecards.dev.

    Returns:
        `(scorecard, status, maintained_is_zero)`.
    """
    quoted = "/".join(quote(part, safe="") for part in source_repo.split("/"))
    url = f"{SCORECARD}/{quoted}"
    try:
        data = await fetch_json(client, url, max_bytes=_SCORECARD_MAX_BYTES)
    except FetchError as exc:
        if exc.code == "http_404":
            return None, "not_found", False
        return None, f"unavailable: {exc.code}", False
    except Exception:  # a malformed Scorecard response must not raise
        logger.exception("Scorecard lookup failed for %s", source_repo)
        return None, "unavailable: error", False
    if not isinstance(data, dict):
        return None, "ok", False
    scorecard, maintained_zero = _scorecard_from_checks(
        data.get("score"), data.get("date"), data.get("checks")
    )
    return scorecard, "ok", maintained_zero


def _adoption_notes(
    *,
    deprecated: bool | None,
    provenance: bool | None,
    scorecard: dict[str, Any] | None,
    maintained_zero: bool,
    license_class: str,
    dependencies: dict[str, Any] | None,
) -> list[str]:
    """Flag concerns worth raising with whoever adopts the package.

    Each string is exact and stable, meant to be matched on by callers,
    not prose: `"deprecated"`, `"no provenance or attestation"`,
    `"Scorecard below 4"`, `"Maintained check scores 0"`,
    `"copyleft licence: raise with the user"`, `"licence unknown"`,
    `"more than 100 transitive dependencies"`, `"has deprecated
    dependencies"`.
    """
    notes: list[str] = []
    if deprecated:
        notes.append("deprecated")
    if provenance is False:
        notes.append("no provenance or attestation")
    if scorecard is not None:
        score = scorecard.get("score")
        if isinstance(score, int | float) and score < 4:
            notes.append("Scorecard below 4")
    if maintained_zero:
        notes.append("Maintained check scores 0")
    if license_class == "copyleft":
        notes.append("copyleft licence: raise with the user")
    elif license_class == "unknown":
        notes.append("licence unknown")
    if dependencies is not None:
        if (dependencies.get("transitive") or 0) > _TRANSITIVE_DEPENDENCY_LIMIT:
            notes.append("more than 100 transitive dependencies")
        if dependencies.get("deprecated"):
            notes.append("has deprecated dependencies")
    return notes


def _unsupported_assessment(
    name: str, version: str, ecosystem: str
) -> PackageAssessment:
    """An assessment for an ecosystem assess_package does not support."""
    return PackageAssessment(
        name=name,
        version=version,
        ecosystem=ecosystem,
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
        sources={"deps_dev": "unsupported_ecosystem"},
    )


async def _assess_action(
    client: httpx.AsyncClient, name: str, version: str, raw_ecosystem: str
) -> PackageAssessment:
    """Assess a GitHub Action: Scorecard only, deps.dev is never queried."""
    source_repo = _action_source_repo(name)
    sources: dict[str, str] = {}
    scorecard: dict[str, Any] | None = None
    maintained_zero = False
    if source_repo is None:
        sources["scorecard"] = "invalid_name"
    else:
        scorecard, sources["scorecard"], maintained_zero = await _fetch_scorecard_api(
            client, source_repo
        )

    adoption_notes = _adoption_notes(
        deprecated=None,
        provenance=None,
        scorecard=scorecard,
        maintained_zero=maintained_zero,
        license_class="unknown",
        dependencies=None,
    )
    return PackageAssessment(
        name=name,
        version=version,
        ecosystem=raw_ecosystem,
        exists=source_repo is not None,
        deprecated=None,
        deprecated_reason=None,
        licenses=[],
        license_class="unknown",
        advisories=[],
        provenance=None,
        source_repo=source_repo,
        scorecard=scorecard,
        dependencies=None,
        adoption_notes=adoption_notes,
        sources=sources,
    )


async def _assess_registry_package(
    client: httpx.AsyncClient, name: str, version: str, raw_ecosystem: str, system: str
) -> PackageAssessment:
    """Assess a pypi/npm package: deps.dev, its project Scorecard, and deps."""
    sources: dict[str, str] = {}
    exists = False
    deprecated: bool | None = None
    deprecated_reason: str | None = None
    licenses: list[str] = []
    advisories: list[str] = []
    provenance: bool | None = None
    source_repo: str | None = None

    data: Any = None
    try:
        data = await _fetch_version_json(client, system, name, version)
    except FetchError as exc:
        sources["deps_dev"] = (
            "not_found" if exc.code == "http_404" else f"unavailable: {exc.code}"
        )
    except Exception:  # a malformed deps.dev response must not fail the call
        logger.exception("deps.dev lookup failed for %s@%s", name, version)
        sources["deps_dev"] = "unavailable: error"
    else:
        sources["deps_dev"] = "ok"

    if isinstance(data, dict):
        exists = True
        deprecated = bool(data.get("isDeprecated", False))
        reason = data.get("deprecatedReason")
        if isinstance(reason, str) and reason:
            deprecated_reason = untrusted(reason, _REASON_TEXT_LIMIT)
        raw_licenses = data.get("licenses")
        if isinstance(raw_licenses, list):
            licenses = [
                untrusted(lic, _LICENSE_TEXT_LIMIT)
                for lic in raw_licenses
                if isinstance(lic, str)
            ][:_MAX_LICENSES]
        raw_advisories = data.get("advisoryKeys")
        if isinstance(raw_advisories, list):
            advisories = [
                untrusted(item["id"], _ADVISORY_ID_LIMIT)
                for item in raw_advisories
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            ][:_MAX_ADVISORIES]
        provenance = bool(data.get("slsaProvenances")) or bool(data.get("attestations"))
        source_repo = _source_repo_from_related(data.get("relatedProjects"))

    license_class = _license_class(licenses)

    scorecard: dict[str, Any] | None = None
    maintained_zero = False
    if source_repo is not None:
        scorecard, scorecard_status, maintained_zero = await _fetch_deps_dev_scorecard(
            client, source_repo
        )
        sources["scorecard"] = scorecard_status

    dependencies: dict[str, Any] | None = None
    if exists:
        dependencies, sources["dependencies"] = await _fetch_dependency_summary(
            client, system, name, version
        )

    adoption_notes = _adoption_notes(
        deprecated=deprecated,
        provenance=provenance,
        scorecard=scorecard,
        maintained_zero=maintained_zero,
        license_class=license_class,
        dependencies=dependencies,
    )

    return PackageAssessment(
        name=name,
        version=version,
        ecosystem=raw_ecosystem,
        exists=exists,
        deprecated=deprecated,
        deprecated_reason=deprecated_reason,
        licenses=licenses,
        license_class=license_class,
        advisories=advisories,
        provenance=provenance,
        source_repo=source_repo,
        scorecard=scorecard,
        dependencies=dependencies,
        adoption_notes=adoption_notes,
        sources=sources,
    )


async def assess_package(
    client: httpx.AsyncClient, name: str, version: str, ecosystem: str
) -> PackageAssessment:
    """Assess one package against deps.dev and the OpenSSF Scorecard.

    This is pre-adoption signal, not an existence check (use
    `sca_verify_packages` for that) and not a verdict: it gathers license,
    provenance, maintenance, and dependency-shape signals for a human or
    agent to weigh. Every source is independent and best effort: a
    failure sets its `sources` entry and leaves the fields it would have
    filled `None` or empty, but this never raises.

    Args:
        client: Client from `new_client`.
        name: Package name, or `owner/repo[/path]` for `github-actions`.
        version: Version string, or the action's ref for `github-actions`.
        ecosystem: `"pypi"` or `"npm"` (or an alias of either), or
            `"github-actions"`. Any other value, including `"container"`,
            is unsupported: the result notes `sources["deps_dev"] ==
            "unsupported_ecosystem"` rather than this raising.

    Returns:
        A `PackageAssessment`.
    """
    eco = _normalize_assess_ecosystem(ecosystem)
    if eco is None:
        return _unsupported_assessment(name, version, ecosystem)
    if eco == "github-actions":
        return await _assess_action(client, name, version, ecosystem)
    return await _assess_registry_package(client, name, version, ecosystem, eco)
