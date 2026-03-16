"""
UDP port scanner — sends protocol-specific probes and interprets
ICMP responses to determine port state.

Requires root for raw ICMP reception (scapy).  Falls back to basic
socket-based probe without root.
"""

from __future__ import annotations

import logging
import socket
from typing import Any, Dict, List, Optional

from shadowprobe.core.config import PortResult, PortState, ScanConfig, ServiceInfo
from shadowprobe.core.scanner import BaseScanner
from shadowprobe.utils.network import is_root, randomize_list, well_known_service

_scapy_available = False
try:
    from scapy.all import IP, UDP, ICMP, sr1
    _scapy_available = True
except ImportError:
    pass


# ── Protocol-specific payloads for common UDP services ──────────────────
_UDP_PAYLOADS: Dict[int, bytes] = {
    53:   b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS query stub
    161:  (  # SNMPv1 public community get-request
        b"\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63"
        b"\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01"
        b"\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
    ),
    123:  b"\xe3\x00\x04\xfa" + b"\x00" * 44,  # NTP version request
    137:  (  # NetBIOS name query
        b"\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
    ),
    1900: b"M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nMan:\"ssdp:discover\"\r\nST:ssdp:all\r\nMX:1\r\n\r\n",
}


class UdpScanner(BaseScanner):
    """Scan UDP ports via protocol-specific probes."""

    def __init__(self, config: ScanConfig, logger: Optional[logging.Logger] = None):
        super().__init__(config, logger)
        self._use_scapy = _scapy_available and is_root()

    def validate(self) -> bool:
        if not self._use_scapy:
            self.log.info(
                "UDP scan without root/scapy may produce less accurate results"
            )
        return True

    def scan(self, targets: List[str], **kwargs: Any) -> dict[str, List[PortResult]]:
        ports = kwargs.get("ports", self.config.ports)
        if self.config.randomize_ports:
            ports = randomize_list(ports)

        self._start_timer()
        results_map: dict[str, List[PortResult]] = {}

        for ip in targets:
            self.log.info("UDP scan: %s (%d ports)", ip, len(ports))
            results_map[ip] = self._scan_host(ip, ports)

        self._stop_timer()
        return results_map

    def _scan_host(self, ip: str, ports: List[int]) -> List[PortResult]:
        results: List[PortResult] = []
        for port in ports:
            pr = self._udp_probe(ip, port)
            if pr:
                results.append(pr)
            self._delay()
        results.sort(key=lambda r: r.port)
        return results

    def _udp_probe(self, ip: str, port: int) -> Optional[PortResult]:
        """Send a UDP probe and interpret the response."""
        payload = _UDP_PAYLOADS.get(port, b"\x00" * 8)

        if self._use_scapy:
            return self._probe_scapy(ip, port, payload)
        return self._probe_socket(ip, port, payload)

    def _probe_scapy(self, ip: str, port: int, payload: bytes) -> Optional[PortResult]:
        try:
            pkt = IP(dst=ip) / UDP(dport=port) / payload
            reply = sr1(pkt, timeout=self.config.timeout, verbose=0)

            if reply is None:
                # No response → open|filtered
                svc_name = well_known_service(port, "udp")
                return PortResult(
                    port=port, protocol="udp", state=PortState.OPEN_FILTERED,
                    service=ServiceInfo(name=svc_name),
                )
            if reply.haslayer(UDP):
                svc_name = well_known_service(port, "udp")
                return PortResult(
                    port=port, protocol="udp", state=PortState.OPEN,
                    service=ServiceInfo(name=svc_name),
                )
            if reply.haslayer(ICMP):
                icmp_type = reply[ICMP].type
                icmp_code = reply[ICMP].code
                if icmp_type == 3 and icmp_code == 3:
                    # Destination unreachable, port unreachable → closed
                    if self.config.verbosity >= 2:
                        return PortResult(
                            port=port, protocol="udp", state=PortState.CLOSED
                        )
                elif icmp_type == 3 and icmp_code in (1, 2, 9, 10, 13):
                    return PortResult(
                        port=port, protocol="udp", state=PortState.FILTERED
                    )
        except Exception as exc:
            self.log.debug("UDP scapy probe %s:%d error: %s", ip, port, exc)
        return None

    def _probe_socket(self, ip: str, port: int, payload: bytes) -> Optional[PortResult]:
        """Fallback UDP probe via standard socket."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.config.timeout)
                s.sendto(payload, (ip, port))
                try:
                    data, _ = s.recvfrom(1024)
                    svc_name = well_known_service(port, "udp")
                    return PortResult(
                        port=port, protocol="udp", state=PortState.OPEN,
                        service=ServiceInfo(name=svc_name),
                    )
                except socket.timeout:
                    svc_name = well_known_service(port, "udp")
                    return PortResult(
                        port=port, protocol="udp", state=PortState.OPEN_FILTERED,
                        service=ServiceInfo(name=svc_name),
                    )
        except OSError as exc:
            self.log.debug("UDP socket probe %s:%d error: %s", ip, port, exc)
        return None

# Available for all to use it.
