"""
TCP-based host discovery — probes common ports to determine if a host
is alive even when ICMP is blocked by firewalls.
"""

from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, List, Optional

from shadowprobe.core.config import HostResult, ScanConfig
from shadowprobe.core.scanner import BaseScanner

# Ports most likely to be open on any live host
_DISCOVERY_PORTS = [80, 443, 22, 21, 25, 8080, 3389, 445]


class TcpDiscovery(BaseScanner):
    """Discover hosts by attempting TCP connections to common ports."""

    def __init__(self, config: ScanConfig, logger: Optional[logging.Logger] = None):
        super().__init__(config, logger)
        self._ports = _DISCOVERY_PORTS

    def scan(self, targets: List[str], **kwargs: Any) -> List[HostResult]:
        """Probe each target on common ports.  One successful connect = host up."""
        self._results.clear()
        self._start_timer()
        self.log.info("Starting TCP discovery on %d host(s)", len(targets))

        max_workers = self.config.effective_threads()
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self._probe_host, ip): ip for ip in targets}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    if result:
                        self._add_result(result)
                except Exception as exc:
                    self.log.debug("TCP discovery failed for %s: %s", ip, exc)

        self._stop_timer()
        self.log.info(
            "TCP discovery complete: %d/%d hosts up (%.2fs)",
            len(self._results), len(targets), self.duration,
        )
        return self.get_results()

    def _probe_host(self, ip: str) -> Optional[HostResult]:
        """Try connecting to common ports; return HostResult on first success."""
        self._delay()
        for port in self._ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.config.timeout)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        return HostResult(
                            ip=ip,
                            is_up=True,
                            discovery_method=f"tcp-probe:{port}",
                        )
            except (socket.timeout, OSError):
                continue
        return None

# Available for all to use it.
