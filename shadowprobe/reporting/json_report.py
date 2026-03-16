"""
JSON report generator for ShadowProbe.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from shadowprobe.core.config import ScanReport
from shadowprobe.reporting.base import BaseReporter

logger = logging.getLogger(__name__)


class JsonReporter(BaseReporter):
    """Generate structured JSON scan reports."""

    def generate(self, report: ScanReport, output_path: Optional[str] = None) -> str:
        """Serialise the report to pretty-printed JSON.

        If *output_path* is given, the file is written and the path returned.
        Otherwise the JSON string is returned.
        """
        data = report.to_dict()

        # Add summary block at the top
        data["summary"] = {
            "total_hosts_scanned": len(report.hosts),
            "hosts_up": len(report.hosts_up),
            "total_open_ports": report.total_open_ports,
            "total_vulnerabilities": report.total_vulns,
            "scan_duration_seconds": round(report.duration, 2),
        }

        json_str = json.dumps(data, indent=2, default=str)

        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json_str, encoding="utf-8")
            logger.info("JSON report written to %s", p)

        return json_str

# Available for all to use it.
