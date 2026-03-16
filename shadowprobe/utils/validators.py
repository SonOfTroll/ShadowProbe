"""
Input validation helpers for ShadowProbe.
"""

import ipaddress
import re
from typing import List, Set


def validate_ip(ip_str: str) -> bool:
    """Return True if *ip_str* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_cidr(cidr_str: str) -> bool:
    """Return True if *cidr_str* is a valid CIDR notation (e.g. 192.168.1.0/24)."""
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """Return True if *port* is in the valid range 1-65535."""
    return isinstance(port, int) and 1 <= port <= 65535


def parse_port_range(port_str: str) -> List[int]:
    """Parse a port specification string into a sorted list of unique ports.

    Supported formats:
        - Single port: ``"80"``
        - Comma-separated: ``"22,80,443"``
        - Range: ``"1-1024"``
        - Mixed: ``"22,80,100-200,443,8000-8100"``
        - Named shortcuts: ``"top100"``, ``"top1000"``, ``"all"``

    Raises:
        ValueError: On invalid port numbers or format.
    """
    port_str = port_str.strip()

    # Named presets
    if port_str.lower() == "all":
        return list(range(1, 65536))
    if port_str.lower() == "top100":
        return _TOP_100_PORTS[:]
    if port_str.lower() == "top1000":
        return _TOP_1000_PORTS[:]

    ports: Set[int] = set()
    for segment in port_str.split(","):
        segment = segment.strip()
        if "-" in segment:
            parts = segment.split("-", 1)
            if len(parts) != 2:
                raise ValueError(f"Invalid port range: {segment}")
            start, end = int(parts[0]), int(parts[1])
            if not (validate_port(start) and validate_port(end) and start <= end):
                raise ValueError(f"Invalid port range: {start}-{end}")
            ports.update(range(start, end + 1))
        else:
            p = int(segment)
            if not validate_port(p):
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def parse_ip_range(range_str: str) -> List[str]:
    """Parse ``10.0.0.1-50`` into a list of IPs.

    Raises:
        ValueError: On malformed range.
    """
    m = re.match(
        r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$", range_str
    )
    if not m:
        raise ValueError(f"Invalid IP range: {range_str}")
    prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
    if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
        raise ValueError(f"Invalid IP range values: {start}-{end}")
    return [f"{prefix}.{i}" for i in range(start, end + 1)]


# ── Well-known port presets ─────────────────────────────────────────────
_TOP_100_PORTS: List[int] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993,
    995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3268, 3306, 3389, 3986, 4899, 5000,
    5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999,
    10000, 32768, 49152, 49153, 49154, 49155,
]

_TOP_1000_PORTS: List[int] = sorted(
    set(_TOP_100_PORTS)
    | set(range(1, 1025))
    | {
        1080, 1194, 1241, 1311, 1434, 1521, 1604, 1812, 1813, 2082, 2083,
        2086, 2087, 2095, 2096, 2222, 2375, 2376, 3268, 3269, 3372, 3690,
        4000, 4443, 4444, 5432, 5500, 5601, 5672, 5901, 5902, 5984, 6379,
        6443, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6697, 7001,
        7002, 7071, 7199, 7443, 7474, 7547, 7657, 7777, 8000, 8001, 8002,
        8008, 8010, 8020, 8031, 8042, 8080, 8081, 8082, 8083, 8084, 8085,
        8086, 8087, 8088, 8089, 8090, 8091, 8118, 8123, 8172, 8222, 8243,
        8280, 8281, 8333, 8337, 8443, 8500, 8530, 8531, 8834, 8880, 8888,
        8983, 9000, 9001, 9002, 9042, 9043, 9060, 9080, 9090, 9091, 9200,
        9300, 9418, 9443, 9500, 9800, 9981, 9999, 10000, 10250, 10443,
        11211, 11214, 11215, 12345, 13579, 14147, 16080, 18080, 19999,
        20000, 25565, 27017, 27018, 27019, 28017, 30000, 32400, 33060,
        37777, 44818, 47001, 49152, 49153, 49154, 49155, 49156, 49157,
        50000, 50030, 50070, 50075, 50090, 51106, 54321, 55555, 61616,
    }
)

# Available for all to use it.
