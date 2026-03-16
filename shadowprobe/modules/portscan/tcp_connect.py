"""
TCP Connect scan — full 3-way handshake port scanner.

Does **not** require root privileges.  This is the default scan type.
"""

from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, List, Optional

from shadowprobe.core.config import PortResult, PortState, ScanConfig, ServiceInfo
from shadowprobe.core.scanner import BaseScanner
from shadowprobe.utils.network import randomize_list, well_known_service


class TcpConnectScanner(BaseScanner):
    """Full TCP connect scan via ``socket.connect_ex()``."""

    def __init__(self, config: ScanConfig, logger: Optional[logging.Logger] = None):
        super().__init__(config, logger)

    def scan(self, targets: List[str], **kwargs: Any) -> dict[str, List[PortResult]]:
        """Scan ports on each target.

        Returns:
            Mapping of IP → list of PortResult.
        """
        ports = kwargs.get("ports", self.config.ports)
        if self.config.randomize_ports:
            ports = randomize_list(ports)

        self._results.clear()
        self._start_timer()
        results_map: dict[str, List[PortResult]] = {}

        for ip in targets:
            self.log.info("TCP connect scan: %s (%d ports)", ip, len(ports))
            port_results = self._scan_host(ip, ports)
            results_map[ip] = port_results

        self._stop_timer()
        return results_map

    def _scan_host(self, ip: str, ports: List[int]) -> List[PortResult]:
        """Scan all ports on a single host concurrently."""
        results: List[PortResult] = []
        max_workers = self.config.effective_threads()

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(self._scan_port, ip, port): port for port in ports
            }
            for future in as_completed(futures):
                port = futures[future]
                try:
                    pr = future.result()
                    if pr:
                        results.append(pr)
                except Exception as exc:
                    self.log.debug("Error scanning %s:%d — %s", ip, port, exc)

        results.sort(key=lambda r: r.port)
        return results

    def _scan_port(self, ip: str, port: int) -> Optional[PortResult]:
        """Attempt a TCP connect to *ip:port*."""
        self._delay()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.config.timeout)
                code = s.connect_ex((ip, port))
                if code == 0:
                    svc_name = well_known_service(port)
                    return PortResult(
                        port=port,
                        protocol="tcp",
                        state=PortState.OPEN,
                        service=ServiceInfo(name=svc_name),
                    )
                else:
                    # Only report closed if verbose
                    if self.config.verbosity >= 2:
                        return PortResult(
                            port=port, protocol="tcp", state=PortState.CLOSED
                        )
        except socket.timeout:
            return PortResult(port=port, protocol="tcp", state=PortState.FILTERED)
        except OSError as exc:
            self.log.debug("connect_ex %s:%d error: %s", ip, port, exc)
        return None

# Available for all to use it.
