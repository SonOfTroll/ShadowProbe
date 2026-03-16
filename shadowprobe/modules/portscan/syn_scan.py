"""
SYN (half-open) stealth scan — sends SYN, reads SYN-ACK/RST,
then sends RST to tear down without completing the handshake.

Requires root privileges and scapy.
"""

from __future__ import annotations

import logging
import random
from typing import Any, List, Optional

from shadowprobe.core.config import PortResult, PortState, ScanConfig, ServiceInfo
from shadowprobe.core.scanner import BaseScanner
from shadowprobe.utils.network import is_root, randomize_list, well_known_service

_scapy_available = False
try:
    from scapy.all import IP, TCP, RandShort, sr1, send, conf as scapy_conf
    _scapy_available = True
except ImportError:
    pass


class SynScanner(BaseScanner):
    """Half-open SYN scan via scapy raw sockets (requires root)."""

    def __init__(self, config: ScanConfig, logger: Optional[logging.Logger] = None):
        super().__init__(config, logger)

    def validate(self) -> bool:
        if not _scapy_available:
            self.log.error("scapy is required for SYN scan but not installed")
            return False
        if not is_root():
            self.log.error("SYN scan requires root/sudo privileges")
            return False
        return True

    def scan(self, targets: List[str], **kwargs: Any) -> dict[str, List[PortResult]]:
        """Run a SYN scan on each target.

        Returns:
            Mapping of IP → list of PortResult.
        """
        if not self.validate():
            return {}

        # Suppress scapy verbosity
        scapy_conf.verb = 0

        ports = kwargs.get("ports", self.config.ports)
        if self.config.randomize_ports:
            ports = randomize_list(ports)

        self._start_timer()
        results_map: dict[str, List[PortResult]] = {}

        for ip in targets:
            self.log.info("SYN scan: %s (%d ports)", ip, len(ports))
            results_map[ip] = self._scan_host(ip, ports)

        self._stop_timer()
        return results_map

    def _scan_host(self, ip: str, ports: List[int]) -> List[PortResult]:
        """SYN-scan all ports on one host sequentially (raw sockets are
        not thread-safe in scapy)."""
        results: List[PortResult] = []
        src_port = int(RandShort())

        for port in ports:
            pr = self._syn_probe(ip, port, src_port)
            if pr:
                results.append(pr)
            self._delay()

        results.sort(key=lambda r: r.port)
        return results

    def _syn_probe(self, ip: str, port: int, src_port: int) -> Optional[PortResult]:
        """Send SYN and interpret the response."""
        try:
            # Build IP layer — optionally with decoys
            ip_layer = IP(dst=ip)

            syn_pkt = ip_layer / TCP(
                sport=src_port, dport=port, flags="S", seq=random.randint(1000, 65535)
            )

            reply = sr1(syn_pkt, timeout=self.config.timeout, verbose=0)

            if reply is None:
                return PortResult(port=port, protocol="tcp", state=PortState.FILTERED)

            tcp_layer = reply.getlayer(TCP)
            if tcp_layer is None:
                return PortResult(port=port, protocol="tcp", state=PortState.FILTERED)

            flags = tcp_layer.flags

            if flags == 0x12:  # SYN-ACK → port open
                # Send RST to tear down (stealth)
                rst = ip_layer / TCP(
                    sport=src_port, dport=port, flags="R", seq=reply.ack
                )
                send(rst, verbose=0)

                svc_name = well_known_service(port)
                return PortResult(
                    port=port,
                    protocol="tcp",
                    state=PortState.OPEN,
                    service=ServiceInfo(name=svc_name),
                )

            elif flags & 0x04:  # RST → port closed
                if self.config.verbosity >= 2:
                    return PortResult(
                        port=port, protocol="tcp", state=PortState.CLOSED
                    )

        except Exception as exc:
            self.log.debug("SYN probe %s:%d error: %s", ip, port, exc)

        return None

# Available for all to use it.
