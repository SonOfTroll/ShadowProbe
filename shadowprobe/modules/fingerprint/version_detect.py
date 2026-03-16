"""
Version fingerprinting — extract product names and version numbers
from service banners using regex pattern matching.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from shadowprobe.core.config import ScanConfig, ServiceInfo
from shadowprobe.core.scanner import BaseScanner


# ── Version extraction patterns ────────────────────────────────────────
# Each entry: (compiled_regex, product_name, version_group_index)
_VERSION_PATTERNS: List[Tuple[re.Pattern, str, int]] = [
    # SSH
    (re.compile(r"SSH-[\d.]+-(OpenSSH)[_\s]*([\d.p]+)", re.I), "OpenSSH", 2),
    (re.compile(r"SSH-[\d.]+-(Dropbear)[_\s]*([\d.]+)", re.I), "Dropbear", 2),
    # HTTP Servers
    (re.compile(r"(Apache)/([\d.]+)", re.I), "Apache httpd", 2),
    (re.compile(r"(nginx)/([\d.]+)", re.I), "nginx", 2),
    (re.compile(r"(Microsoft-IIS)/([\d.]+)", re.I), "Microsoft IIS", 2),
    (re.compile(r"(lighttpd)/([\d.]+)", re.I), "lighttpd", 2),
    (re.compile(r"(LiteSpeed).*?/([\d.]+)", re.I), "LiteSpeed", 2),
    # Mail
    (re.compile(r"(Postfix)", re.I), "Postfix", 0),
    (re.compile(r"(Exim)\s*([\d.]+)", re.I), "Exim", 2),
    (re.compile(r"(Dovecot)\s*ready", re.I), "Dovecot", 0),
    (re.compile(r"(Microsoft ESMTP MAIL)", re.I), "Microsoft Exchange SMTP", 0),
    # FTP
    (re.compile(r"(vsftpd)\s*([\d.]+)", re.I), "vsftpd", 2),
    (re.compile(r"(ProFTPD)\s*([\d.]+)", re.I), "ProFTPD", 2),
    (re.compile(r"(Pure-FTPd)", re.I), "Pure-FTPd", 0),
    (re.compile(r"(FileZilla Server)\s*([\d.]+)", re.I), "FileZilla Server", 2),
    # Databases
    (re.compile(r"(MySQL|MariaDB).*?([\d.]+)", re.I), "MySQL/MariaDB", 2),
    (re.compile(r"(PostgreSQL)\s*([\d.]+)", re.I), "PostgreSQL", 2),
    (re.compile(r"(Redis).*?v=([\d.]+)", re.I), "Redis", 2),
    (re.compile(r"(MongoDB).*?([\d.]+)", re.I), "MongoDB", 2),
    # Miscellaneous
    (re.compile(r"(Squid)/([\d.]+)", re.I), "Squid", 2),
    (re.compile(r"(Varnish).*?([\d.]+)", re.I), "Varnish", 2),
    (re.compile(r"(PHP)/([\d.]+)", re.I), "PHP", 2),
    (re.compile(r"(Node\.js|node)\s*v?([\d.]+)", re.I), "Node.js", 2),
    (re.compile(r"(Tomcat)/([\d.]+)", re.I), "Apache Tomcat", 2),
    (re.compile(r"(Jetty).*?([\d.]+)", re.I), "Jetty", 2),
    (re.compile(r"(RabbitMQ)\s*([\d.]+)", re.I), "RabbitMQ", 2),
]


class VersionDetector(BaseScanner):
    """Extract product names and version numbers from banners."""

    def __init__(self, config: ScanConfig, logger: Optional[logging.Logger] = None):
        super().__init__(config, logger)

    def scan(self, targets: List[str], **kwargs: Any) -> Dict[str, Dict[int, ServiceInfo]]:
        """Analyse banners and enrich ServiceInfo with product/version.

        Expects ``banners`` kwarg: dict of IP → { port: ServiceInfo }.

        Returns the same structure, mutated with product/version.
        """
        banners: Dict[str, Dict[int, ServiceInfo]] = kwargs.get("banners", {})
        self._start_timer()

        for ip in targets:
            host_banners = banners.get(ip, {})
            for port, svc in host_banners.items():
                if svc.banner:
                    self._enrich(svc)

        self._stop_timer()
        return banners

    def _enrich(self, svc: ServiceInfo) -> None:
        """Try each pattern against the banner, pick highest confidence."""
        best_product = ""
        best_version = ""
        best_confidence = 0

        for pattern, product_name, ver_group in _VERSION_PATTERNS:
            m = pattern.search(svc.banner)
            if m:
                version = ""
                try:
                    version = m.group(ver_group) if ver_group else ""
                except IndexError:
                    pass

                # Confidence heuristic: specific version > product only
                confidence = 70 if version else 40

                if confidence > best_confidence:
                    best_product = product_name
                    best_version = version
                    best_confidence = confidence

        if best_product:
            svc.product = best_product
            svc.version = best_version
            svc.confidence = best_confidence
            self.log.debug(
                "Identified: %s %s (confidence %d%%)",
                best_product, best_version, best_confidence,
            )

# Available for all to use it.
