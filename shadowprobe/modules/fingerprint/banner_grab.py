"""
Banner grabbing — raw socket connections to grab service banners.

Supports protocol-aware probes for HTTP, SMTP, FTP, SSH, and
SSL/TLS certificate extraction.
"""

from __future__ import annotations

import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from shadowprobe.core.config import ScanConfig, ServiceInfo
from shadowprobe.core.scanner import BaseScanner


# ── Protocol-specific probe payloads ────────────────────────────────────
_PROBES: Dict[str, bytes] = {
    "http":  b"HEAD / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
    "https": b"HEAD / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
    "smtp":  b"EHLO shadowprobe.local\r\n",
    "ftp":   b"",           # FTP sends banner on connect
    "ssh":   b"",           # SSH sends banner on connect
    "pop3":  b"",           # POP3 sends banner on connect
    "imap":  b"",           # IMAP sends banner on connect
    "mysql": b"",           # MySQL sends greeting on connect
}

# Ports that typically use SSL/TLS
_SSL_PORTS = {443, 465, 636, 993, 995, 8443, 9443}

# Map port numbers to protocol probe keys
_PORT_PROTO: Dict[int, str] = {
    21: "ftp", 22: "ssh", 25: "smtp", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 465: "smtp", 587: "smtp",
    993: "imap", 995: "pop3", 3306: "mysql", 8080: "http",
    8443: "https",
}


class BannerGrabber(BaseScanner):
    """Grab service banners from open ports."""

    def __init__(self, config: ScanConfig, logger: Optional[logging.Logger] = None):
        super().__init__(config, logger)

    def scan(self, targets: List[str], **kwargs: Any) -> Dict[str, Dict[int, ServiceInfo]]:
        """Grab banners for open ports on each target.

        Expects ``open_ports`` kwarg: dict of IP → list of (port, proto).

        Returns:
            Mapping of IP → { port: ServiceInfo }.
        """
        open_ports: Dict[str, List[Tuple[int, str]]] = kwargs.get("open_ports", {})
        self._start_timer()
        results: Dict[str, Dict[int, ServiceInfo]] = {}

        for ip in targets:
            ports_for_host = open_ports.get(ip, [])
            if not ports_for_host:
                continue
            self.log.info("Banner grab: %s (%d ports)", ip, len(ports_for_host))
            results[ip] = self._grab_host(ip, ports_for_host)

        self._stop_timer()
        return results

    def _grab_host(
        self, ip: str, ports: List[Tuple[int, str]]
    ) -> Dict[int, ServiceInfo]:
        """Grab banners concurrently for one host."""
        results: Dict[int, ServiceInfo] = {}
        max_workers = min(self.config.effective_threads(), 20)

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futs = {
                pool.submit(self._grab_port, ip, port): port
                for port, _proto in ports
            }
            for future in as_completed(futs):
                port = futs[future]
                try:
                    si = future.result()
                    if si:
                        results[port] = si
                except Exception as exc:
                    self.log.debug("Banner grab %s:%d error: %s", ip, port, exc)

        return results

    def _grab_port(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Grab the banner from a single port."""
        self._delay()
        use_ssl = port in _SSL_PORTS
        proto_key = _PORT_PROTO.get(port, "")
        probe = _PROBES.get(proto_key, b"")

        # Replace placeholder in HTTP probes
        if proto_key in ("http", "https"):
            probe = probe.replace(b"target", ip.encode())

        banner = ""
        ssl_subject = ""

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(self.config.timeout)
            raw_sock.connect((ip, port))

            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
                # Extract certificate subject
                cert = sock.getpeercert(True)
                if cert:
                    import ssl as _ssl
                    decoded = _ssl.DER_cert_to_PEM_cert(cert)
                    ssl_subject = decoded[:200]  # first 200 chars
            else:
                sock = raw_sock

            if probe:
                sock.sendall(probe)

            data = sock.recv(4096)
            banner = data.decode("utf-8", errors="replace").strip()
            sock.close()

        except Exception as exc:
            self.log.debug("Banner grab %s:%d: %s", ip, port, exc)

        if not banner:
            return None

        return ServiceInfo(
            banner=banner[:2048],
            ssl=use_ssl,
            ssl_cert_subject=ssl_subject[:500],
        )

# Available for all to use it.
