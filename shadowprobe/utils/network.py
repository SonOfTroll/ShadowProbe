"""
Network helper utilities for ShadowProbe.
"""

import os
import random
import socket
from typing import Optional


def resolve_hostname(hostname: str, timeout: float = 5.0) -> Optional[str]:
    """Resolve a hostname to an IPv4 address.

    Returns:
        The IP string, or ``None`` on failure.
    """
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def reverse_dns(ip: str, timeout: float = 3.0) -> Optional[str]:
    """Perform reverse DNS lookup for *ip*.

    Returns:
        The hostname string, or ``None`` on failure.
    """
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def is_root() -> bool:
    """Return True if the process is running with root / CAP_NET_RAW."""
    return os.geteuid() == 0


def get_local_ip() -> str:
    """Heuristic to determine the primary local IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def randomize_list(items: list, seed: Optional[int] = None) -> list:
    """Return a shuffled copy of *items* (for scan order randomization)."""
    shuffled = items[:]
    rng = random.Random(seed)
    rng.shuffle(shuffled)
    return shuffled


def apply_jitter(delay: float, jitter_pct: float = 0.2) -> float:
    """Return *delay* with ± *jitter_pct* random variation.

    Example:
        ``apply_jitter(1.0, 0.2)`` → value in [0.8, 1.2]
    """
    if delay <= 0:
        return 0.0
    jitter = delay * jitter_pct
    return max(0.0, delay + random.uniform(-jitter, jitter))


def well_known_service(port: int, proto: str = "tcp") -> str:
    """Return the well-known service name for a port, or ``'unknown'``."""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


def calculate_checksum(data: bytes) -> int:
    """Compute an Internet checksum (RFC 1071) over *data*."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF

# Available for all to use it.
