"""
Safety layer: SSRF protection, rate limiting, consent validation.
"""

import ipaddress
import os
import socket
import time
from collections import defaultdict
from threading import Lock
from urllib.parse import urlparse
from typing import Optional

# ---------------------------------------------------------------------------
# SSRF / Private-IP Denylist
# ---------------------------------------------------------------------------

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]
EXPLICIT_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
}

_raw_whitelist = os.environ.get("ALLOWED_PRIVATE_TARGETS", "")
WHITELISTED_HOSTS: set[str] = {
    host.strip().lower() for host in _raw_whitelist.split(",") if host.strip()
}


def _resolve_host(url: str) -> Optional[str]:
    """Extract hostname from URL."""
    try:
        host = urlparse(url).hostname or ""
        return host.lower()
    except Exception:
        return None


def _resolve_ips(host: str) -> list[ipaddress._BaseAddress]:
    """Resolve a hostname to IP addresses for SSRF checks."""
    addresses: list[ipaddress._BaseAddress] = []
    try:
        results = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return addresses

    for result in results:
        sockaddr = result[4]
        if not sockaddr:
            continue
        try:
            addresses.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue

    unique: list[ipaddress._BaseAddress] = []
    seen = set()
    for address in addresses:
        if address.compressed not in seen:
            seen.add(address.compressed)
            unique.append(address)
    return unique


def is_ssrf_blocked(url: str) -> tuple[bool, str]:
    """
    Returns (blocked: bool, reason: str).
    Blocks localhost, private networks, and cloud metadata IPs unless whitelisted.
    """
    host = _resolve_host(url)
    if not host:
        return True, "Could not parse hostname from URL."

    if host in WHITELISTED_HOSTS:
        return False, ""

    if host in {"localhost", "local", "ip6-localhost", "ip6-loopback"}:
        return True, "Scanning localhost is not allowed unless the target is explicitly whitelisted."

    try:
        resolved_ips = [ipaddress.ip_address(host)]
    except ValueError:
        resolved_ips = _resolve_ips(host)
        if not resolved_ips:
            return (
                True,
                "Could not safely resolve the target hostname. "
                "Only resolvable public targets or explicitly whitelisted private targets may be scanned.",
            )

    for ip in resolved_ips:
        if ip in EXPLICIT_METADATA_IPS:
            return (
                True,
                "Scanning cloud metadata endpoints is not allowed. "
                "Whitelist only if this is your own infrastructure and you fully understand the risk.",
            )
        for net in PRIVATE_NETWORKS:
            if ip in net:
                return (
                    True,
                    f"Resolved target IP {ip.compressed} is in blocked range {net}. "
                    "Add the hostname or IP to ALLOWED_PRIVATE_TARGETS only for infrastructure you own.",
                )

    return False, ""


# ---------------------------------------------------------------------------
# Rate Limiter (in-memory, per-IP sliding window + per-session concurrency)
# ---------------------------------------------------------------------------

_lock = Lock()
_scan_log: dict[str, list[float]] = defaultdict(list)
_active_scans_by_ip: dict[str, int] = defaultdict(int)
_active_scans_by_session: dict[str, int] = defaultdict(int)

MAX_CONCURRENT_PER_SESSION = 1
MAX_PER_HOUR_PER_IP = 5
WINDOW_SECONDS = 3600


def check_rate_limit(ip: str, session_id: str) -> tuple[bool, str]:
    """
    Returns (allowed: bool, reason: str).
    Call BEFORE starting a scan.
    """
    now = time.time()
    with _lock:
        _scan_log[ip] = [timestamp for timestamp in _scan_log[ip] if now - timestamp < WINDOW_SECONDS]

        if _active_scans_by_session[session_id] >= MAX_CONCURRENT_PER_SESSION:
            return False, "You already have a scan in progress in this session. Wait for it to complete."

        if len(_scan_log[ip]) >= MAX_PER_HOUR_PER_IP:
            return False, f"Rate limit exceeded: maximum {MAX_PER_HOUR_PER_IP} scans per hour per IP."

        _scan_log[ip].append(now)
        _active_scans_by_ip[ip] += 1
        _active_scans_by_session[session_id] += 1
        return True, ""


def release_rate_limit_slot(ip: str, session_id: str):
    """Call AFTER a scan finishes (success or failure) to free the concurrent slot."""
    with _lock:
        if _active_scans_by_ip[ip] > 0:
            _active_scans_by_ip[ip] -= 1
        if _active_scans_by_session[session_id] > 0:
            _active_scans_by_session[session_id] -= 1
