"""
ShadowProbe — Scan Orchestrator.

Coordinates the full pipeline:
  1. Parse targets
  2. Host discovery
  3. Port scanning
  4. Banner grabbing & fingerprinting
  5. Vulnerability checking
  6. OS detection
  7. Report generation
"""

from __future__ import annotations

import logging
import signal
import time
import uuid
from typing import Dict, List, Optional, Tuple

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from shadowprobe.core.config import (
    HostResult,
    PortResult,
    PortState,
    ScanConfig,
    ScanReport,
    ScanType,
)
from shadowprobe.core.target import TargetParser
from shadowprobe.modules.discovery.arp_scan import ArpScanner
from shadowprobe.modules.discovery.ping_sweep import PingSweep
from shadowprobe.modules.discovery.tcp_discovery import TcpDiscovery
from shadowprobe.modules.fingerprint.banner_grab import BannerGrabber
from shadowprobe.modules.fingerprint.os_detect import OsDetector
from shadowprobe.modules.fingerprint.version_detect import VersionDetector
from shadowprobe.modules.fingerprint.vuln_check import VulnChecker
from shadowprobe.modules.portscan.syn_scan import SynScanner
from shadowprobe.modules.portscan.tcp_connect import TcpConnectScanner
from shadowprobe.modules.portscan.udp_scan import UdpScanner
from shadowprobe.reporting.html_report import HtmlReporter
from shadowprobe.reporting.json_report import JsonReporter
from shadowprobe.utils.logger import console


class ScanOrchestrator:
    """Coordinates all scan phases into a single pipeline."""

    def __init__(self, config: ScanConfig, logger: Optional[logging.Logger] = None):
        self.config = config
        self.log = logger or logging.getLogger(self.__class__.__name__)
        self.report = ScanReport(
            scan_id=str(uuid.uuid4())[:8],
            config=config,
        )
        self._interrupted = False
        signal.signal(signal.SIGINT, self._handle_interrupt)

    # ── Public ──────────────────────────────────────────────────────

    def run(self, command_str: str = "") -> ScanReport:
        """Execute the full scan pipeline and return the report."""
        self.report.command = command_str
        self.report.start_time = time.time()

        try:
            # 1. Parse targets
            targets = self._parse_targets()
            if not targets:
                self.report.errors.append("No valid targets resolved")
                return self._finalise()

            # 2. Host discovery
            live_hosts = self._discover(targets)
            if not live_hosts and self.config.discovery:
                console.print("[yellow]⚠ No live hosts found. Scanning all targets anyway...[/yellow]")
                live_hosts = {ip: HostResult(ip=ip, is_up=True, discovery_method="forced") for ip in targets}

            if self._interrupted:
                return self._finalise()

            # 3. Port scanning
            port_results = self._portscan(list(live_hosts.keys()))

            if self._interrupted:
                return self._finalise()

            # 4. Merge port results into host results
            self._merge_ports(live_hosts, port_results)

            # 5. Fingerprinting (banner grab → version detect → vuln check → OS detect)
            if self.config.fingerprint:
                self._fingerprint(live_hosts)

            # 6. Build report
            self.report.hosts = list(live_hosts.values())

        except Exception as exc:
            self.log.error("Scan pipeline error: %s", exc, exc_info=True)
            self.report.errors.append(str(exc))

        return self._finalise()

    def generate_report(self) -> str:
        """Generate the output report based on config format."""
        fmt = self.config.output_format.lower()
        if fmt == "html":
            reporter = HtmlReporter()
        else:
            reporter = JsonReporter()

        return reporter.generate(self.report, self.config.output_file)

    # ── Phase 1: Target parsing ─────────────────────────────────────

    def _parse_targets(self) -> List[str]:
        console.print("[cyan]⚡ Parsing targets...[/cyan]")
        parser = TargetParser(logger=self.log)
        try:
            targets = parser.parse_targets(self.config.targets)
            console.print(f"[green]  ✓ {len(targets)} target(s) resolved[/green]")
            return targets
        except ValueError as exc:
            self.log.error("Target parsing error: %s", exc)
            self.report.errors.append(f"Target error: {exc}")
            return []

    # ── Phase 2: Discovery ──────────────────────────────────────────

    def _discover(self, targets: List[str]) -> Dict[str, HostResult]:
        """Run host discovery and return a dict of IP → HostResult."""
        if not self.config.discovery:
            console.print("[dim]  ⏭ Discovery skipped[/dim]")
            return {ip: HostResult(ip=ip, is_up=True, discovery_method="skipped")
                    for ip in targets}

        console.print("[cyan]🔍 Running host discovery...[/cyan]")
        live: Dict[str, HostResult] = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Discovery", total=len(targets))

            # Try ARP first (fast, reliable on LAN)
            arp = ArpScanner(self.config, logger=self.log)
            if arp.validate():
                for hr in arp.scan(targets):
                    live[hr.ip] = hr
                    progress.advance(task)

            # ICMP ping sweep for remaining targets
            remaining = [ip for ip in targets if ip not in live]
            if remaining:
                ping = PingSweep(self.config, logger=self.log)
                for hr in ping.scan(remaining):
                    live[hr.ip] = hr
                    progress.advance(task)

            # TCP discovery for any still-undiscovered targets
            remaining = [ip for ip in targets if ip not in live]
            if remaining:
                tcp_disc = TcpDiscovery(self.config, logger=self.log)
                for hr in tcp_disc.scan(remaining):
                    live[hr.ip] = hr
                    progress.advance(task)

            # Complete progress for hosts not found
            progress.update(task, completed=len(targets))

        console.print(f"[green]  ✓ {len(live)}/{len(targets)} host(s) up[/green]")
        return live

    # ── Phase 3: Port scanning ──────────────────────────────────────

    def _portscan(self, targets: List[str]) -> Dict[str, List[PortResult]]:
        """Run port scans and return merged results per host."""
        console.print("[cyan]🔌 Running port scan...[/cyan]")
        all_results: Dict[str, List[PortResult]] = {}

        for scan_type in self.config.scan_types:
            if self._interrupted:
                break

            scanner: Optional[object] = None
            if scan_type == ScanType.CONNECT:
                scanner = TcpConnectScanner(self.config, logger=self.log)
            elif scan_type == ScanType.SYN:
                scanner = SynScanner(self.config, logger=self.log)
                if not scanner.validate():
                    console.print("[yellow]  ⚠ SYN scan unavailable, falling back to connect[/yellow]")
                    scanner = TcpConnectScanner(self.config, logger=self.log)
            elif scan_type == ScanType.UDP:
                scanner = UdpScanner(self.config, logger=self.log)

            if scanner:
                results = scanner.scan(targets, ports=self.config.ports)
                for ip, ports in results.items():
                    existing = all_results.get(ip, [])
                    existing.extend(ports)
                    all_results[ip] = existing

        # Deduplicate and count
        total_open = sum(
            1 for ports in all_results.values()
            for p in ports if p.state == PortState.OPEN
        )
        console.print(f"[green]  ✓ {total_open} open port(s) found[/green]")
        return all_results

    # ── Phase 4: Merge ──────────────────────────────────────────────

    def _merge_ports(
        self,
        hosts: Dict[str, HostResult],
        port_results: Dict[str, List[PortResult]],
    ) -> None:
        """Merge port scan results into HostResult objects."""
        for ip, ports in port_results.items():
            if ip in hosts:
                hosts[ip].ports = ports
            else:
                hosts[ip] = HostResult(ip=ip, is_up=True, ports=ports)

    # ── Phase 5: Fingerprinting ─────────────────────────────────────

    def _fingerprint(self, hosts: Dict[str, HostResult]) -> None:
        """Run banner grab → version detect → vuln check → OS detect."""
        console.print("[cyan]🔎 Running fingerprinting...[/cyan]")

        # Build open_ports map for fingerprinting
        open_ports: Dict[str, List[Tuple[int, str]]] = {}
        for ip, hr in hosts.items():
            ops = [(p.port, p.protocol) for p in hr.ports if p.state == PortState.OPEN]
            if ops:
                open_ports[ip] = ops

        targets = list(open_ports.keys())
        if not targets:
            console.print("[dim]  ⏭ No open ports to fingerprint[/dim]")
            return

        # Banner grabbing
        bg = BannerGrabber(self.config, logger=self.log)
        banners = bg.scan(targets, open_ports=open_ports)
        banner_count = sum(len(b) for b in banners.values())
        console.print(f"[green]  ✓ {banner_count} banner(s) grabbed[/green]")

        # Version detection
        vd = VersionDetector(self.config, logger=self.log)
        vd.scan(targets, banners=banners)

        # Merge banners back into port results
        for ip, port_banners in banners.items():
            if ip in hosts:
                for port_result in hosts[ip].ports:
                    if port_result.port in port_banners:
                        si = port_banners[port_result.port]
                        # Merge fields (keep non-empty)
                        if si.banner:
                            port_result.service.banner = si.banner
                        if si.product:
                            port_result.service.product = si.product
                        if si.version:
                            port_result.service.version = si.version
                        if si.confidence:
                            port_result.service.confidence = si.confidence
                        if si.ssl:
                            port_result.service.ssl = si.ssl
                        if si.ssl_cert_subject:
                            port_result.service.ssl_cert_subject = si.ssl_cert_subject

        # Vulnerability checking
        if self.config.vuln_check:
            vc = VulnChecker(self.config, logger=self.log)
            vuln_results = vc.scan(targets, banners=banners)
            vuln_count = sum(
                len(v) for hv in vuln_results.values() for v in hv.values()
            )
            if vuln_count:
                console.print(f"[red]  ⚠ {vuln_count} vulnerability/ies found[/red]")
            else:
                console.print("[green]  ✓ No known vulnerabilities detected[/green]")

            # Merge vulns into port results
            for ip, port_vulns in vuln_results.items():
                if ip in hosts:
                    for port_result in hosts[ip].ports:
                        if port_result.port in port_vulns:
                            port_result.service.vulnerabilities = port_vulns[port_result.port]

        # OS detection
        if self.config.os_detect:
            od = OsDetector(self.config, logger=self.log)
            host_results_map = {ip: hr for ip, hr in hosts.items()}
            od.scan(targets, host_results=host_results_map, banners=banners)

    # ── Helpers ─────────────────────────────────────────────────────

    def _finalise(self) -> ScanReport:
        self.report.end_time = time.time()
        console.print(
            f"\n[bold cyan]⚡ Scan complete in {self.report.duration:.2f}s — "
            f"{len(self.report.hosts_up)} host(s), "
            f"{self.report.total_open_ports} open port(s), "
            f"{self.report.total_vulns} vuln(s)[/bold cyan]\n"
        )
        return self.report

    def _handle_interrupt(self, signum: int, frame) -> None:
        console.print("\n[yellow]⚠ Scan interrupted by user — generating partial report...[/yellow]")
        self._interrupted = True
        self.report.errors.append("Scan interrupted by user (SIGINT)")

# Available for all to use it.
