"""
Service detection via python-nmap integration.

Falls back to well-known port-to-service mapping if nmap is
not available on the system.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from shadowprobe.core.config import PortResult, PortState, ScanConfig, ServiceInfo
from shadowprobe.core.scanner import BaseScanner
from shadowprobe.utils.network import well_known_service

_nmap_available = False
try:
    import nmap
    _nmap_available = True
except ImportError:
    pass


class ServiceDetector(BaseScanner):
    """Detect services on open ports via nmap -sV or fallback heuristics."""

    def __init__(self, config: ScanConfig, logger: Optional[logging.Logger] = None):
        super().__init__(config, logger)
        self._nm = None
        if _nmap_available:
            try:
                self._nm = nmap.PortScanner()
            except nmap.PortScannerError:
                self.log.warning("nmap binary not found — service detection limited")

    def validate(self) -> bool:
        if self._nm is None:
            self.log.info("nmap not available — using fallback service detection")
        return True

    def scan(self, targets: List[str], **kwargs: Any) -> dict[str, List[PortResult]]:
        """Detect services on open ports for each target.

        Expects ``open_ports`` kwarg as a dict mapping IP → list of
        (port, protocol) tuples.  If not provided, scans the configured
        ports.
        """
        open_ports: Dict[str, List[tuple]] = kwargs.get("open_ports", {})
        self._start_timer()
        results_map: dict[str, List[PortResult]] = {}

        for ip in targets:
            ports_for_host = open_ports.get(ip, [])
            if not ports_for_host:
                continue
            self.log.info("Service detection: %s (%d ports)", ip, len(ports_for_host))
            if self._nm:
                results_map[ip] = self._detect_nmap(ip, ports_for_host)
            else:
                results_map[ip] = self._detect_fallback(ip, ports_for_host)

        self._stop_timer()
        return results_map

    def _detect_nmap(self, ip: str, ports: List[tuple]) -> List[PortResult]:
        """Use python-nmap for comprehensive service version detection."""
        results: List[PortResult] = []
        port_str = ",".join(str(p) for p, _ in ports)
        try:
            self._nm.scan(ip, port_str, arguments="-sV --version-intensity 5")
            if ip not in self._nm.all_hosts():
                return results

            for proto in self._nm[ip].all_protocols():
                for port in self._nm[ip][proto]:
                    svc = self._nm[ip][proto][port]
                    si = ServiceInfo(
                        name=svc.get("name", "unknown"),
                        product=svc.get("product", ""),
                        version=svc.get("version", ""),
                        extra_info=svc.get("extrainfo", ""),
                        confidence=int(svc.get("conf", "0")),
                        cpe=svc.get("cpe", ""),
                    )
                    state_str = svc.get("state", "open")
                    state = PortState.OPEN if state_str == "open" else PortState.FILTERED
                    results.append(PortResult(
                        port=port, protocol=proto, state=state, service=si
                    ))
        except Exception as exc:
            self.log.error("nmap service detect error for %s: %s", ip, exc)

        results.sort(key=lambda r: r.port)
        return results

    def _detect_fallback(self, ip: str, ports: List[tuple]) -> List[PortResult]:
        """Simple port-to-service-name mapping."""
        results: List[PortResult] = []
        for port, proto in ports:
            svc_name = well_known_service(port, proto)
            results.append(PortResult(
                port=port,
                protocol=proto,
                state=PortState.OPEN,
                service=ServiceInfo(name=svc_name),
            ))
        results.sort(key=lambda r: r.port)
        return results

# Available for all to use it.
