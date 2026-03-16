"""
Scan configuration and result data structures for ShadowProbe.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Enums ───────────────────────────────────────────────────────────────

class ScanType(Enum):
    """Supported scan types."""
    CONNECT = "connect"
    SYN     = "syn"
    UDP     = "udp"
    SERVICE = "service"


class TimingProfile(Enum):
    """Timing profiles (inspired by nmap T0–T5)."""
    PARANOID  = "paranoid"      # T0 — 5 s delay
    SNEAKY    = "sneaky"        # T1 — 0.4 s
    POLITE    = "polite"        # T2 — 0.1 s
    NORMAL    = "normal"        # T3 — 0 s
    AGGRESSIVE = "aggressive"   # T4 — 0 s, higher concurrency
    INSANE    = "insane"        # T5 — 0 s, max concurrency

    @property
    def delay(self) -> float:
        """Inter-packet delay in seconds."""
        return {
            TimingProfile.PARANOID:   5.0,
            TimingProfile.SNEAKY:     0.4,
            TimingProfile.POLITE:     0.1,
            TimingProfile.NORMAL:     0.0,
            TimingProfile.AGGRESSIVE: 0.0,
            TimingProfile.INSANE:     0.0,
        }[self]

    @property
    def max_threads(self) -> int:
        """Recommended max concurrent threads."""
        return {
            TimingProfile.PARANOID:   1,
            TimingProfile.SNEAKY:     5,
            TimingProfile.POLITE:     10,
            TimingProfile.NORMAL:     50,
            TimingProfile.AGGRESSIVE: 150,
            TimingProfile.INSANE:     300,
        }[self]


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class PortState(Enum):
    """Port scan result states."""
    OPEN          = "open"
    CLOSED        = "closed"
    FILTERED      = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNKNOWN       = "unknown"


# ── Data Classes ────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    """All parameters controlling a scan run."""
    targets: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    scan_types: List[ScanType] = field(default_factory=lambda: [ScanType.CONNECT])
    timing: TimingProfile = TimingProfile.NORMAL
    threads: int = 50
    timeout: float = 3.0
    retries: int = 1
    stealth: bool = False
    randomize_ports: bool = True
    randomize_hosts: bool = False
    output_file: Optional[str] = None
    output_format: str = "json"
    discovery: bool = True
    fingerprint: bool = True
    vuln_check: bool = True
    os_detect: bool = True
    verbosity: int = 0
    interface: Optional[str] = None
    decoys: List[str] = field(default_factory=list)

    def effective_threads(self) -> int:
        """Return thread count capped by timing profile."""
        return min(self.threads, self.timing.max_threads)

    def effective_delay(self) -> float:
        """Return the inter-packet delay from the timing profile."""
        return self.timing.delay


@dataclass
class VulnInfo:
    """A single vulnerability finding."""
    cve_id: str = ""
    title: str = ""
    severity: Severity = Severity.INFO
    cvss: float = 0.0
    description: str = ""
    affected_versions: str = ""
    reference: str = ""


@dataclass
class ServiceInfo:
    """Service fingerprinting result for a single port."""
    name: str = "unknown"
    product: str = ""
    version: str = ""
    banner: str = ""
    extra_info: str = ""
    confidence: int = 0          # 0-100
    cpe: str = ""
    ssl: bool = False
    ssl_cert_subject: str = ""
    vulnerabilities: List[VulnInfo] = field(default_factory=list)


@dataclass
class PortResult:
    """Result of scanning a single port."""
    port: int = 0
    protocol: str = "tcp"
    state: PortState = PortState.UNKNOWN
    service: ServiceInfo = field(default_factory=ServiceInfo)


@dataclass
class HostResult:
    """Aggregated results for a single target host."""
    ip: str = ""
    hostname: str = ""
    is_up: bool = False
    mac_address: str = ""
    vendor: str = ""
    os_guess: str = ""
    os_confidence: int = 0
    ttl: int = 0
    discovery_method: str = ""
    ports: List[PortResult] = field(default_factory=list)
    scan_start: float = 0.0
    scan_end: float = 0.0

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == PortState.OPEN]

    @property
    def all_vulns(self) -> List[VulnInfo]:
        vulns: List[VulnInfo] = []
        for p in self.ports:
            vulns.extend(p.service.vulnerabilities)
        return vulns

    @property
    def duration(self) -> float:
        return self.scan_end - self.scan_start if self.scan_end else 0.0


@dataclass
class ScanReport:
    """Top-level scan report aggregating all results."""
    scan_id: str = ""
    command: str = ""
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    config: Optional[ScanConfig] = None
    hosts: List[HostResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time else 0.0

    @property
    def hosts_up(self) -> List[HostResult]:
        return [h for h in self.hosts if h.is_up]

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    @property
    def total_vulns(self) -> int:
        return sum(len(h.all_vulns) for h in self.hosts)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the full report to a plain dict (JSON-ready)."""
        import dataclasses

        def _convert(obj: Any) -> Any:
            if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
                d = {}
                for f in dataclasses.fields(obj):
                    val = getattr(obj, f.name)
                    d[f.name] = _convert(val)
                return d
            if isinstance(obj, list):
                return [_convert(v) for v in obj]
            if isinstance(obj, Enum):
                return obj.value
            return obj

        return _convert(self)

# Available for all to use it.
