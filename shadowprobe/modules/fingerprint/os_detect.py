"""
OS fingerprinting — detect the operating system family from network
behaviour clues (TTL values, TCP window sizes, banner strings).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from shadowprobe.core.config import HostResult, ScanConfig, ServiceInfo
from shadowprobe.core.scanner import BaseScanner


# ── TTL-based OS family heuristic ───────────────────────────────────────
_TTL_TABLE = [
    (range(1, 65),    "Linux/Unix"),     # Default TTL 64
    (range(65, 129),  "Windows"),        # Default TTL 128
    (range(129, 256), "Network Device"), # Cisco/Solaris TTL 255
]

# ── Banner string clues ────────────────────────────────────────────────
_BANNER_CLUES = [
    (re.compile(r"ubuntu", re.I),       "Ubuntu Linux"),
    (re.compile(r"debian", re.I),       "Debian Linux"),
    (re.compile(r"centos", re.I),       "CentOS Linux"),
    (re.compile(r"red\s*hat", re.I),    "Red Hat Enterprise Linux"),
    (re.compile(r"fedora", re.I),       "Fedora Linux"),
    (re.compile(r"alpine", re.I),       "Alpine Linux"),
    (re.compile(r"arch\s*linux", re.I), "Arch Linux"),
    (re.compile(r"FreeBSD", re.I),      "FreeBSD"),
    (re.compile(r"OpenBSD", re.I),      "OpenBSD"),
    (re.compile(r"Win64|Win32|Windows", re.I), "Windows"),
    (re.compile(r"Microsoft", re.I),    "Windows"),
    (re.compile(r"IOS|Cisco", re.I),    "Cisco IOS"),
    (re.compile(r"RouterOS", re.I),     "MikroTik RouterOS"),
]


class OsDetector(BaseScanner):
    """Detect the OS family from TTL, banners, and other network clues."""

    def __init__(self, config: ScanConfig, logger: Optional[logging.Logger] = None):
        super().__init__(config, logger)

    def scan(self, targets: List[str], **kwargs: Any) -> Dict[str, dict]:
        """Fingerprint OS for each host.

        Expects:
            - ``host_results`` kwarg: dict of IP → HostResult
            - ``banners`` kwarg: dict of IP → { port: ServiceInfo }

        Returns:
            Mapping of IP → { "os_guess": str, "confidence": int }.
        """
        host_results: Dict[str, HostResult] = kwargs.get("host_results", {})
        banners: Dict[str, Dict[int, ServiceInfo]] = kwargs.get("banners", {})
        self._start_timer()
        os_map: Dict[str, dict] = {}

        for ip in targets:
            hr = host_results.get(ip)
            host_banners = banners.get(ip, {})
            guess, confidence = self._detect(ip, hr, host_banners)
            os_map[ip] = {"os_guess": guess, "confidence": confidence}
            if hr:
                hr.os_guess = guess
                hr.os_confidence = confidence
            self.log.debug("OS for %s: %s (%d%%)", ip, guess, confidence)

        self._stop_timer()
        return os_map

    def _detect(
        self,
        ip: str,
        hr: Optional[HostResult],
        banners: Dict[int, ServiceInfo],
    ) -> tuple[str, int]:
        """Combine TTL and banner clues to guess the OS."""
        candidates: Dict[str, int] = {}  # os_name → weight

        # ── TTL analysis ────────────────────────────────────────────
        if hr and hr.ttl > 0:
            for rng, os_family in _TTL_TABLE:
                if hr.ttl in rng:
                    candidates[os_family] = candidates.get(os_family, 0) + 30
                    break

        # ── Banner clue analysis ────────────────────────────────────
        all_banners = " ".join(svc.banner for svc in banners.values())
        for pattern, os_name in _BANNER_CLUES:
            if pattern.search(all_banners):
                candidates[os_name] = candidates.get(os_name, 0) + 50

        if not candidates:
            return ("Unknown", 0)

        best_os = max(candidates, key=candidates.get)  # type: ignore[arg-type]
        # Normalise confidence to 0..100
        raw = candidates[best_os]
        confidence = min(raw, 95)
        return (best_os, confidence)

# Available for all to use it.
