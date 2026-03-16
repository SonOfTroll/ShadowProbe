"""
HTML report generator for ShadowProbe.

Uses Jinja2 to render a dark-themed, self-contained HTML report.
"""

from __future__ import annotations

import datetime
import logging
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from shadowprobe.core.config import ScanReport
from shadowprobe.reporting.base import BaseReporter

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent.parent / "templates"


class HtmlReporter(BaseReporter):
    """Render a rich, dark-themed HTML scan report."""

    def generate(self, report: ScanReport, output_path: Optional[str] = None) -> str:
        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )

        # Custom filters
        env.filters["severity_color"] = self._severity_color
        env.filters["timestamp"] = self._format_ts

        template = env.get_template("report.html")

        # Prepare summary data
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for host in report.hosts:
            for vuln in host.all_vulns:
                severity_counts[vuln.severity.value] = severity_counts.get(
                    vuln.severity.value, 0
                ) + 1

        html = template.render(
            report=report,
            summary={
                "total_hosts": len(report.hosts),
                "hosts_up": len(report.hosts_up),
                "open_ports": report.total_open_ports,
                "total_vulns": report.total_vulns,
                "duration": round(report.duration, 2),
                "severity_counts": severity_counts,
            },
            generated_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(html, encoding="utf-8")
            logger.info("HTML report written to %s", p)

        return html

    @staticmethod
    def _severity_color(severity_val: str) -> str:
        colors = {
            "critical": "#ff1744",
            "high":     "#ff5252",
            "medium":   "#ffa726",
            "low":      "#66bb6a",
            "info":     "#42a5f5",
        }
        return colors.get(severity_val, "#9e9e9e")

    @staticmethod
    def _format_ts(ts: float) -> str:
        if not ts:
            return "N/A"
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

# Available for all to use it.
