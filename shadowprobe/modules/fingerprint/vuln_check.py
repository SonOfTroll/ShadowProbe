"""
Vulnerability checker — matches detected service versions against
a local vulnerability signature database.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from shadowprobe.core.config import ScanConfig, ServiceInfo, Severity, VulnInfo
from shadowprobe.core.scanner import BaseScanner


_DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data"
_VULN_DB_PATH = _DATA_DIR / "vuln_signatures.json"


def _parse_version(v: str) -> Tuple[int, ...]:
    """Parse a dotted version string into a tuple of integers for comparison."""
    parts = []
    for p in v.split("."):
        # Strip non-numeric suffixes like "p1"
        num = ""
        for ch in p:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    return tuple(parts)


def _version_in_range(version: str, min_ver: str, max_ver: str) -> bool:
    """Check if *version* falls within [min_ver, max_ver]."""
    try:
        v = _parse_version(version)
        lo = _parse_version(min_ver) if min_ver else (0,)
        hi = _parse_version(max_ver) if max_ver else (999, 999, 999)
        return lo <= v <= hi
    except (ValueError, TypeError):
        return False


class VulnChecker(BaseScanner):
    """Check detected services against a local vulnerability database."""

    def __init__(self, config: ScanConfig, logger: Optional[logging.Logger] = None):
        super().__init__(config, logger)
        self._db: List[Dict] = []
        self._load_db()

    def _load_db(self) -> None:
        """Load the vulnerability signatures JSON."""
        if not _VULN_DB_PATH.exists():
            self.log.warning("Vulnerability DB not found at %s", _VULN_DB_PATH)
            return
        try:
            self._db = json.loads(_VULN_DB_PATH.read_text(encoding="utf-8"))
            self.log.debug("Loaded %d vuln signatures", len(self._db))
        except (json.JSONDecodeError, OSError) as exc:
            self.log.error("Failed to load vuln DB: %s", exc)

    def scan(self, targets: List[str], **kwargs: Any) -> Dict[str, Dict[int, List[VulnInfo]]]:
        """Match detected services against vulnerabilities.

        Expects ``banners`` kwarg: dict IP → { port: ServiceInfo }.

        Returns mapping of IP → { port: [VulnInfo] }.
        """
        banners: Dict[str, Dict[int, ServiceInfo]] = kwargs.get("banners", {})
        self._start_timer()
        results: Dict[str, Dict[int, List[VulnInfo]]] = {}

        for ip in targets:
            host_banners = banners.get(ip, {})
            host_vulns: Dict[int, List[VulnInfo]] = {}
            for port, svc in host_banners.items():
                vulns = self._check_service(svc)
                if vulns:
                    host_vulns[port] = vulns
                    svc.vulnerabilities.extend(vulns)
            if host_vulns:
                results[ip] = host_vulns

        self._stop_timer()
        total_vulns = sum(
            len(v) for hv in results.values() for v in hv.values()
        )
        self.log.info("Vulnerability check: %d finding(s)", total_vulns)
        return results

    def _check_service(self, svc: ServiceInfo) -> List[VulnInfo]:
        """Check a single ServiceInfo against the vuln DB."""
        if not svc.product or not svc.version:
            return []

        findings: List[VulnInfo] = []
        product_lower = svc.product.lower()

        for sig in self._db:
            sig_product = sig.get("product", "").lower()
            if sig_product not in product_lower and product_lower not in sig_product:
                continue
            min_ver = sig.get("min_version", "")
            max_ver = sig.get("max_version", "")
            if _version_in_range(svc.version, min_ver, max_ver):
                severity = Severity.INFO
                try:
                    severity = Severity(sig.get("severity", "info").lower())
                except ValueError:
                    pass
                findings.append(VulnInfo(
                    cve_id=sig.get("cve_id", ""),
                    title=sig.get("title", ""),
                    severity=severity,
                    cvss=float(sig.get("cvss", 0)),
                    description=sig.get("description", ""),
                    affected_versions=f"{min_ver} — {max_ver}",
                    reference=sig.get("reference", ""),
                ))

        return findings

# Available for all to use it.
