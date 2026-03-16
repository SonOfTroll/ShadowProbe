"""Unit tests for report generation."""

import json
import tempfile
from pathlib import Path

import pytest

from shadowprobe.core.config import (
    HostResult,
    PortResult,
    PortState,
    ScanConfig,
    ScanReport,
    ServiceInfo,
    Severity,
    VulnInfo,
)
from shadowprobe.reporting.json_report import JsonReporter
from shadowprobe.reporting.html_report import HtmlReporter


@pytest.fixture
def sample_report():
    """Build a sample ScanReport for testing."""
    vuln = VulnInfo(
        cve_id="CVE-2024-0001",
        title="Test Vulnerability",
        severity=Severity.HIGH,
        cvss=7.5,
        description="A test vulnerability for unit testing.",
        affected_versions="1.0 — 2.0",
        reference="https://example.com/cve",
    )
    svc = ServiceInfo(
        name="http",
        product="Apache httpd",
        version="2.4.50",
        banner="Apache/2.4.50 (Ubuntu)",
        confidence=80,
        vulnerabilities=[vuln],
    )
    port = PortResult(port=80, protocol="tcp", state=PortState.OPEN, service=svc)
    host = HostResult(
        ip="192.168.1.100",
        hostname="test-server",
        is_up=True,
        os_guess="Ubuntu Linux",
        os_confidence=70,
        ttl=64,
        discovery_method="icmp-echo",
        ports=[port],
        scan_start=1000.0,
        scan_end=1005.0,
    )
    report = ScanReport(
        scan_id="test-001",
        command="shadowprobe scan -t 192.168.1.100",
        start_time=1000.0,
        end_time=1010.0,
        config=ScanConfig(),
        hosts=[host],
    )
    return report


class TestJsonReport:
    def test_generate_string(self, sample_report):
        reporter = JsonReporter()
        output = reporter.generate(sample_report)
        data = json.loads(output)
        assert "summary" in data
        assert data["summary"]["hosts_up"] == 1
        assert data["summary"]["total_open_ports"] == 1
        assert data["summary"]["total_vulnerabilities"] == 1

    def test_generate_file(self, sample_report, tmp_path):
        out_file = str(tmp_path / "test_report.json")
        reporter = JsonReporter()
        reporter.generate(sample_report, output_path=out_file)
        assert Path(out_file).exists()
        data = json.loads(Path(out_file).read_text())
        assert data["scan_id"] == "test-001"

    def test_to_dict_enums_serialized(self, sample_report):
        d = sample_report.to_dict()
        # Ensure enums are serialized as strings
        host = d["hosts"][0]
        port = host["ports"][0]
        assert port["state"] == "open"
        assert port["service"]["vulnerabilities"][0]["severity"] == "high"


class TestHtmlReport:
    def test_generate_contains_html(self, sample_report):
        reporter = HtmlReporter()
        output = reporter.generate(sample_report)
        assert "<!DOCTYPE html>" in output
        assert "SHADOWPROBE" in output
        assert "192.168.1.100" in output
        assert "CVE-2024-0001" in output

    def test_generate_file(self, sample_report, tmp_path):
        out_file = str(tmp_path / "test_report.html")
        reporter = HtmlReporter()
        reporter.generate(sample_report, output_path=out_file)
        assert Path(out_file).exists()
        content = Path(out_file).read_text()
        assert "Apache httpd" in content
