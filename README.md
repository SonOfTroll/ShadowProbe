# ShadowProbe

<div align="center">

```
  ____  _               _                ____            _
 / ___|| |__   __ _  __| | _____      __/ _  \ _ __ ___ | |__   ___
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / |_) | '__/ _ \| '_ \ / _ \
  ___) | | | | (_| | (_| | (_) \ V  V /|  __/| | | (_) | |_) |  __/
 |____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_|   |_|  \___/|_.__/ \___|
```

**Advanced Network Reconnaissance & Vulnerability Scanner**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

</div>

---

## ⚠️ Legal Disclaimer

**ShadowProbe is designed for authorized penetration testing and network security assessments only.** Unauthorized network scanning is illegal in most jurisdictions. Always obtain explicit written permission before scanning any network or system you do not own.

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **Host Discovery** | ICMP ping sweep, ARP scanning (LAN), TCP probe discovery |
| **Port Scanning** | TCP connect, SYN stealth (half-open), UDP with protocol payloads |
| **Service Detection** | python-nmap integration + fallback well-known port mapping |
| **Banner Grabbing** | Protocol-aware probes (HTTP, SMTP, FTP, SSH) + SSL cert extraction |
| **Version Fingerprinting** | Regex-based detection for 25+ services (Apache, nginx, OpenSSH, MySQL…) |
| **Vulnerability Checking** | Local CVE database with 28 signatures, version range matching |
| **OS Detection** | TTL analysis + banner clue aggregation for 13+ OS families |
| **Stealth & Evasion** | Timing profiles (T0–T5), port randomization, SYN stealth, jitter |
| **Rich Reports** | Dark-themed HTML reports + structured JSON output |
| **Modular Architecture** | Pluggable scanner modules with abstract base classes |

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/youruser/ShadowProbe.git
cd ShadowProbe

# Install in development mode
pip install -e .

# Or install dependencies only
pip install -r requirements.txt
```

### System Dependencies

- **Python 3.9+**
- **nmap** (optional, for deep service detection): `sudo apt install nmap`
- **Root/sudo** required for: SYN scans, ARP discovery, ICMP raw sockets

---

## 🖥️ Usage

### Full Scan (Default Pipeline)

```bash
# Basic scan — TCP connect on top 100 ports
shadowprobe scan -t 192.168.1.0/24

# Scan specific ports with JSON output
shadowprobe scan -t 10.0.0.1 -p 22,80,443,8080 -o report.json

# SYN stealth scan (requires root)
sudo shadowprobe scan -t 192.168.1.1 -sT syn -p top1000

# Full scan with HTML report
shadowprobe scan -t 10.0.0.1-50 -p 1-1024 -f html -o report.html

# Stealth mode — sneaky timing, SYN scan, port randomization
sudo shadowprobe scan -t target.com --stealth -o stealth_report.json
```

### Host Discovery Only

```bash
shadowprobe discover -t 192.168.1.0/24
```

### Port Scan Only (No Discovery)

```bash
shadowprobe portscan -t 10.0.0.1 -p 1-65535 -sT connect
```

### Advanced Options

```bash
# Multiple scan types simultaneously
sudo shadowprobe scan -t 10.0.0.1 -sT connect syn udp -p top1000

# Paranoid timing (5s delay between packets)
shadowprobe scan -t target.com -T paranoid -p 22,80,443

# Aggressive timing with more threads
shadowprobe scan -t 10.0.0.1 -T aggressive --threads 200

# Verbose output (INFO level)
shadowprobe scan -t 10.0.0.1 -p 80,443 -v

# Debug output (DEBUG level)
shadowprobe scan -t 10.0.0.1 -p 80 -vv

# Skip specific phases
shadowprobe scan -t 10.0.0.1 --no-discovery --no-os-detect

# Scan targets from a file
shadowprobe scan -t file:/path/to/targets.txt -p top100
```

### As a Python Module

```bash
python -m shadowprobe scan -t 127.0.0.1 -p 22,80,443 -f json
```

---

## 📊 Report Examples

### JSON Report Structure

```json
{
  "scan_id": "a1b2c3d4",
  "command": "shadowprobe scan -t 10.0.0.1",
  "summary": {
    "total_hosts_scanned": 1,
    "hosts_up": 1,
    "total_open_ports": 3,
    "total_vulnerabilities": 2,
    "scan_duration_seconds": 12.45
  },
  "hosts": [
    {
      "ip": "10.0.0.1",
      "os_guess": "Ubuntu Linux",
      "ports": [
        {
          "port": 22,
          "state": "open",
          "service": {
            "name": "ssh",
            "product": "OpenSSH",
            "version": "8.9",
            "vulnerabilities": [...]
          }
        }
      ]
    }
  ]
}
```

### HTML Report

The HTML report features a dark-themed UI with:
- Executive summary cards (hosts, ports, vulns)
- Severity distribution badges
- Per-host details with port/service tables
- Vulnerability cards with CVE references and CVSS scores

---

## 🏗️ Architecture

```
shadowprobe/
├── core/
│   ├── scanner.py        # BaseScanner ABC — thread-safe, timing-aware
│   ├── target.py         # TargetParser — CIDR, ranges, files, hostnames
│   └── config.py         # Dataclasses: ScanConfig, HostResult, PortResult,
│                         #              ServiceInfo, VulnInfo, ScanReport
├── modules/
│   ├── discovery/        # PingSweep, ArpScanner, TcpDiscovery
│   ├── portscan/         # TcpConnect, SynScanner, UdpScanner, ServiceDetector
│   └── fingerprint/      # BannerGrabber, VersionDetector, VulnChecker, OsDetector
├── reporting/
│   ├── json_report.py    # Structured JSON output
│   └── html_report.py    # Jinja2 dark-themed HTML
├── utils/
│   ├── logger.py         # Rich-powered colored logging
│   ├── network.py        # DNS, checksums, jitter, root detection
│   └── validators.py     # IP/port validation, port range parsing
├── cli.py                # argparse CLI with subcommands
├── orchestrator.py       # 6-phase pipeline coordinator
└── __main__.py           # Entry point
```

### Scan Pipeline

```
Targets → Parse → Discover → Port Scan → Banner Grab → Version Detect
                                                          ↓
                              Report ← OS Detect ← Vuln Check
```

---

## 🛡️ Evasion Techniques

| Technique | Description | Flag |
|-----------|-------------|------|
| **Timing Profiles** | T0 (5s delay) to T5 (max speed) | `-T paranoid` |
| **SYN Stealth** | Half-open connections avoid connection logs | `-sT syn` |
| **Port Randomization** | Avoids sequential scan detection | Default (disable: `--no-randomize`) |
| **Jitter** | ±20% random variation on inter-packet delays | Automatic with timing |
| **Stealth Mode** | Combines sneaky timing + SYN scan + randomization | `--stealth` |

---

## 🧪 Testing

```bash
# Run all unit tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=shadowprobe

# Quick smoke test against localhost
python -m shadowprobe scan -t 127.0.0.1 -p 22,80,443 -f json
```

---

## 📋 Dependencies

| Package | Purpose |
|---------|---------|
| `scapy` | Raw packet crafting (SYN scan, ARP, ICMP) |
| `python-nmap` | Nmap integration for service detection |
| `jinja2` | HTML report template rendering |
| `rich` | Colored console output and progress bars |

---

## 📄 License

MIT License — see [LICENSE](./LICENSE) for details.

---

<div align="center">
<sub>Built for authorized security professionals. Use responsibly.</sub>
</div>
