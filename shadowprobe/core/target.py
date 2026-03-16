"""
Target parsing and resolution for ShadowProbe.

Supports:
  - Single IPs:        ``192.168.1.1``
  - CIDR notation:     ``10.0.0.0/24``
  - IP ranges:         ``10.0.0.1-50``
  - Hostnames:         ``scanme.nmap.org``
  - Comma-separated:   ``192.168.1.1,192.168.1.2``
  - File input:        ``file:/path/to/targets.txt``
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import List, Optional

from shadowprobe.utils.network import resolve_hostname
from shadowprobe.utils.validators import parse_ip_range, validate_cidr, validate_ip


class TargetParser:
    """Parse a user-supplied target specification into a flat list of IPs."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.log = logger or logging.getLogger(self.__class__.__name__)

    def parse(self, target_spec: str) -> List[str]:
        """Parse one target spec token and return a list of IP strings.

        Raises:
            ValueError: On unresolvable / invalid input.
        """
        spec = target_spec.strip()
        if not spec:
            return []

        # ── File input ──────────────────────────────────────────────
        if spec.startswith("file:"):
            return self._from_file(spec[5:])

        # ── Comma-separated list ────────────────────────────────────
        if "," in spec:
            ips: List[str] = []
            for part in spec.split(","):
                ips.extend(self.parse(part))
            return ips

        # ── CIDR ────────────────────────────────────────────────────
        if "/" in spec and validate_cidr(spec):
            net = ipaddress.ip_network(spec, strict=False)
            return [str(h) for h in net.hosts()] or [str(net.network_address)]

        # ── IP range  (10.0.0.1-50) ─────────────────────────────────
        if "-" in spec and "." in spec:
            try:
                return parse_ip_range(spec)
            except ValueError:
                pass  # Fall through to single-address / hostname

        # ── Single IP ───────────────────────────────────────────────
        if validate_ip(spec):
            return [spec]

        # ── Hostname ────────────────────────────────────────────────
        resolved = resolve_hostname(spec)
        if resolved:
            self.log.info("Resolved %s → %s", spec, resolved)
            return [resolved]

        raise ValueError(f"Cannot resolve target: {spec}")

    def parse_targets(self, specs: List[str]) -> List[str]:
        """Parse multiple target specs and return a deduplicated list."""
        seen: set[str] = set()
        results: List[str] = []
        for spec in specs:
            for ip in self.parse(spec):
                if ip not in seen:
                    seen.add(ip)
                    results.append(ip)
        return results

    # ── Private ─────────────────────────────────────────────────────
    def _from_file(self, path_str: str) -> List[str]:
        """Read targets line-by-line from a file."""
        p = Path(path_str.strip())
        if not p.is_file():
            raise ValueError(f"Target file not found: {p}")
        ips: List[str] = []
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.extend(self.parse(line))
        return ips

# Available for all to use it.
