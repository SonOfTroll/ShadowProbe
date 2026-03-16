"""
ICMP Ping Sweep — discover live hosts via echo requests.

Uses scapy when available (and running as root), otherwise falls back
to the system ``ping`` command via subprocess.
"""

from __future__ import annotations

import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, List, Optional

from shadowprobe.core.config import HostResult, ScanConfig
from shadowprobe.core.scanner import BaseScanner
from shadowprobe.utils.network import is_root

# Lazy scapy import — it's heavy and may not be installed everywhere
_scapy_available = False
try:
    from scapy.all import ICMP, IP, sr1
    _scapy_available = True
except ImportError:
    pass


class PingSweep(BaseScanner):
    """Discover live hosts by sending ICMP echo requests."""

    def __init__(self, config: ScanConfig, logger: Optional[logging.Logger] = None):
        super().__init__(config, logger)
        self._use_scapy = _scapy_available and is_root()

    def validate(self) -> bool:
        if not self._use_scapy:
            self.log.info(
                "Raw ICMP not available (no scapy or not root) — "
                "falling back to subprocess ping"
            )
        return True

    def scan(self, targets: List[str], **kwargs: Any) -> List[HostResult]:
        """Ping-sweep the target list and return HostResult objects for live hosts."""
        self._results.clear()
        self._start_timer()
        self.log.info("Starting ping sweep on %d host(s)", len(targets))

        max_workers = self.config.effective_threads()
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self._ping_host, ip): ip for ip in targets}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    if result:
                        self._add_result(result)
                except Exception as exc:
                    self.log.debug("Ping failed for %s: %s", ip, exc)

        self._stop_timer()
        self.log.info(
            "Ping sweep complete: %d/%d hosts up (%.2fs)",
            len(self._results), len(targets), self.duration,
        )
        return self.get_results()

    # ── Private ─────────────────────────────────────────────────────
    def _ping_host(self, ip: str) -> Optional[HostResult]:
        """Ping a single host. Returns HostResult if alive, else None."""
        self._delay()
        if self._use_scapy:
            return self._ping_scapy(ip)
        return self._ping_subprocess(ip)

    def _ping_scapy(self, ip: str) -> Optional[HostResult]:
        """Send ICMP echo via scapy."""
        try:
            pkt = IP(dst=ip) / ICMP()
            reply = sr1(pkt, timeout=self.config.timeout, verbose=0)
            if reply and reply.haslayer(ICMP):
                ttl = reply[IP].ttl
                return HostResult(
                    ip=ip,
                    is_up=True,
                    ttl=ttl,
                    discovery_method="icmp-echo",
                )
        except Exception as exc:
            self.log.debug("Scapy ICMP to %s failed: %s", ip, exc)
        return None

    def _ping_subprocess(self, ip: str) -> Optional[HostResult]:
        """Fallback: use system ``ping`` command."""
        try:
            timeout_s = str(max(1, int(self.config.timeout)))
            cmd = ["ping", "-c", "1", "-W", timeout_s, ip]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=float(timeout_s) + 2
            )
            if proc.returncode == 0:
                ttl = self._extract_ttl(proc.stdout)
                return HostResult(
                    ip=ip,
                    is_up=True,
                    ttl=ttl,
                    discovery_method="icmp-subprocess",
                )
        except (subprocess.TimeoutExpired, OSError) as exc:
            self.log.debug("Subprocess ping to %s failed: %s", ip, exc)
        return None

    @staticmethod
    def _extract_ttl(ping_output: str) -> int:
        """Parse TTL from ping output, e.g. ``ttl=64``."""
        import re
        m = re.search(r"ttl[=:](\d+)", ping_output, re.IGNORECASE)
        return int(m.group(1)) if m else 0

# Available for all to use it.
