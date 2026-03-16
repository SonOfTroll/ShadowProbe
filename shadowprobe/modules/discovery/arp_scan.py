"""
ARP-based host discovery — fast and reliable on the local subnet.

Sends ARP who-has requests via scapy ``srp()`` and collects responses
including MAC addresses and optional OUI vendor lookup.
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from shadowprobe.core.config import HostResult, ScanConfig
from shadowprobe.core.scanner import BaseScanner
from shadowprobe.utils.network import is_root

_scapy_available = False
try:
    from scapy.all import ARP, Ether, srp
    _scapy_available = True
except ImportError:
    pass


# ── Minimal OUI vendor lookup (top vendors) ─────────────────────────────
_OUI_TABLE = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1c:42": "Parallels",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "00:1a:2b": "Cisco",
    "00:14:22": "Dell",
    "3c:d9:2b": "HP",
    "f0:de:f1": "Apple",
    "a4:83:e7": "Apple",
}


def _lookup_vendor(mac: str) -> str:
    """Best-effort vendor lookup from MAC OUI prefix."""
    prefix = mac.lower()[:8]
    return _OUI_TABLE.get(prefix, "")


class ArpScanner(BaseScanner):
    """Discover hosts on the local subnet via ARP requests."""

    def __init__(self, config: ScanConfig, logger: Optional[logging.Logger] = None):
        super().__init__(config, logger)

    def validate(self) -> bool:
        if not _scapy_available:
            self.log.warning("scapy not available — ARP scan disabled")
            return False
        if not is_root():
            self.log.warning("ARP scan requires root privileges")
            return False
        return True

    def scan(self, targets: List[str], **kwargs: Any) -> List[HostResult]:
        """Send ARP requests to *targets* and return discovered hosts.

        Typically called with a CIDR-expanded list of IPs on the local
        subnet.
        """
        if not self.validate():
            return []

        self._results.clear()
        self._start_timer()
        self.log.info("Starting ARP scan on %d target(s)", len(targets))

        try:
            iface = self.config.interface
            # Build ARP requests as Ether/ARP frames
            for batch_start in range(0, len(targets), 256):
                batch = targets[batch_start : batch_start + 256]
                pkts = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=batch)
                ans, _unans = srp(
                    pkts,
                    timeout=self.config.timeout,
                    verbose=0,
                    iface=iface,
                )
                for _sent, recv in ans:
                    ip = recv[ARP].psrc
                    mac = recv[Ether].src
                    vendor = _lookup_vendor(mac)
                    self._add_result(
                        HostResult(
                            ip=ip,
                            is_up=True,
                            mac_address=mac,
                            vendor=vendor,
                            discovery_method="arp",
                        )
                    )
                self._delay()
        except Exception as exc:
            self.log.error("ARP scan error: %s", exc)

        self._stop_timer()
        self.log.info(
            "ARP scan complete: %d host(s) discovered (%.2fs)",
            len(self._results), self.duration,
        )
        return self.get_results()

# Available for all to use it.
