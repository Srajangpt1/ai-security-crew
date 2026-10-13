"""Rewrite anything that points at the outside world to reserved addresses."""

import hashlib
import ipaddress
import re

URL_RE = re.compile(r"https?://[^\s'\"`)>;|\\]+")
IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
TLDS = "com|net|org|io|gov|edu|info|xyz|ru|cn|de|uk|me|co|dev|app|cc|tv"
HOST_RE = re.compile(rf"\b(?:[a-z0-9-]+\.)+(?:{TLDS})\b", re.IGNORECASE)
KEEP_HOSTS = {"localhost"}
DOC_NETS = [
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
]


def _digest(text: str) -> int:
    """Return a stable integer for ``text``."""
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest(), 16)


def _keep_ip(text: str) -> bool:
    """Tell whether an IP may stay as-is (private, loopback, link-local, docs)."""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return True
    if ip.is_link_local:
        return False
    return ip.is_private or ip.is_loopback or ip.is_unspecified


def _rewrite_url(match: re.Match[str]) -> str:
    """Replace one URL, keeping local ones."""
    url = match.group(0)
    host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
    if host in KEEP_HOSTS or (IP_RE.fullmatch(host) and _keep_ip(host)):
        return url
    segment = re.sub(r"[^A-Za-z0-9._-]", "", url.rstrip("/").split("/")[-1])
    if "." not in host or segment == host:
        segment = "p"
    return f"https://attacker.example/{segment[:24] or 'p'}"


def _rewrite_ip(match: re.Match[str]) -> str:
    """Replace a public IPv4 address with a documentation address."""
    text = match.group(1)
    if _keep_ip(text):
        return text
    net = DOC_NETS[_digest(text) % 2]
    return str(net.network_address + 1 + _digest(text + "h") % 250)


def _rewrite_host(match: re.Match[str]) -> str:
    """Replace a bare domain name with a name under ``.example``."""
    host = match.group(0)
    if host.lower().endswith(".example"):
        return host
    return f"host{_digest(host.lower()) % 1000:03d}.example"


def sanitize(command: str) -> str:
    """Remove real hosts from a command.

    URLs become ``https://attacker.example/<path>``, bare domains become
    ``hostNNN.example`` and public IPv4 addresses become documentation addresses.
    Local paths and private addresses are kept.

    Args:
        command: Shell command after placeholder substitution.

    Returns:
        The command with external endpoints rewritten.
    """
    out = URL_RE.sub(_rewrite_url, command)
    out = IP_RE.sub(_rewrite_ip, out)
    return HOST_RE.sub(_rewrite_host, out)
