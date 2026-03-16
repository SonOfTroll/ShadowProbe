"""
Command-line interface for ShadowProbe.

Provides ``argparse``-based CLI with subcommands for scan, discover,
and portscan workflows.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from shadowprobe import __version__
from shadowprobe.core.config import ScanConfig, ScanType, TimingProfile
from shadowprobe.utils.validators import parse_port_range


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="shadowprobe",
        description=(
            "ShadowProbe — Advanced Network Reconnaissance "
            "& Vulnerability Scanner"
        ),
        epilog="⚠  For authorized security testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-V", "--version", action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── scan (full pipeline) ────────────────────────────────────────
    scan_p = subparsers.add_parser(
        "scan", help="Full reconnaissance pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common_args(scan_p)
    scan_p.add_argument(
        "--no-discovery", action="store_true",
        help="Skip host discovery (treat all targets as up)",
    )
    scan_p.add_argument(
        "--no-fingerprint", action="store_true",
        help="Skip banner grabbing and version detection",
    )
    scan_p.add_argument(
        "--no-vuln-check", action="store_true",
        help="Skip vulnerability checking",
    )
    scan_p.add_argument(
        "--no-os-detect", action="store_true",
        help="Skip OS fingerprinting",
    )

    # ── discover ────────────────────────────────────────────────────
    disc_p = subparsers.add_parser(
        "discover", help="Host discovery only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_target_args(disc_p)
    _add_output_args(disc_p)
    _add_timing_args(disc_p)

    # ── portscan ────────────────────────────────────────────────────
    ps_p = subparsers.add_parser(
        "portscan", help="Port scan only (skip discovery)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common_args(ps_p)

    return parser


def _add_target_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "-t", "--targets", nargs="+", required=True,
        help="Target(s): IPs, CIDRs, ranges, hostnames, or file:path",
    )
    p.add_argument(
        "--interface", "-i", default=None,
        help="Network interface to use (e.g. eth0)",
    )
    p.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase verbosity (-v, -vv)",
    )


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "-o", "--output", default=None,
        help="Output file path",
    )
    p.add_argument(
        "-f", "--format", choices=["json", "html"], default="json",
        help="Output format (default: json)",
    )


def _add_timing_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "-T", "--timing", choices=[t.value for t in TimingProfile],
        default="normal",
        help="Timing profile: paranoid/sneaky/polite/normal/aggressive/insane",
    )
    p.add_argument(
        "--threads", type=int, default=50,
        help="Max concurrent threads (default: 50)",
    )
    p.add_argument(
        "--timeout", type=float, default=3.0,
        help="Socket timeout in seconds (default: 3.0)",
    )
    p.add_argument(
        "--stealth", action="store_true",
        help="Enable stealth evasion techniques",
    )


def _add_common_args(p: argparse.ArgumentParser) -> None:
    _add_target_args(p)
    _add_output_args(p)
    _add_timing_args(p)
    p.add_argument(
        "-p", "--ports", default="top100",
        help="Port specification: single, range, comma-separated, "
             "or presets (top100/top1000/all). Default: top100",
    )
    p.add_argument(
        "-sT", "--scan-type", nargs="+",
        choices=["connect", "syn", "udp", "service"],
        default=["connect"],
        help="Scan type(s) (default: connect)",
    )
    p.add_argument(
        "--no-randomize", action="store_true",
        help="Disable port order randomization",
    )
    p.add_argument(
        "--decoys", nargs="*", default=[],
        help="Decoy source IPs for SYN scan evasion",
    )


def parse_args(argv: Optional[List[str]] = None) -> ScanConfig:
    """Parse CLI arguments and return a populated ScanConfig."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    config = ScanConfig()
    config.targets = getattr(args, "targets", [])
    config.verbosity = getattr(args, "verbose", 0)
    config.interface = getattr(args, "interface", None)
    config.output_file = getattr(args, "output", None)
    config.output_format = getattr(args, "format", "json")
    config.timing = TimingProfile(getattr(args, "timing", "normal"))
    config.threads = getattr(args, "threads", 50)
    config.timeout = getattr(args, "timeout", 3.0)
    config.stealth = getattr(args, "stealth", False)
    config.decoys = getattr(args, "decoys", [])

    # Port parsing
    port_str = getattr(args, "ports", "top100")
    try:
        config.ports = parse_port_range(port_str)
    except ValueError as exc:
        parser.error(f"Invalid port specification: {exc}")

    # Scan types
    scan_types_raw = getattr(args, "scan_type", ["connect"])
    config.scan_types = [ScanType(st) for st in scan_types_raw]

    # Feature flags
    config.randomize_ports = not getattr(args, "no_randomize", False)

    if args.command == "scan":
        config.discovery = not args.no_discovery
        config.fingerprint = not args.no_fingerprint
        config.vuln_check = not args.no_vuln_check
        config.os_detect = not args.no_os_detect
    elif args.command == "discover":
        config.discovery = True
        config.fingerprint = False
        config.vuln_check = False
        config.os_detect = False
        config.ports = []
    elif args.command == "portscan":
        config.discovery = False
        config.fingerprint = False
        config.vuln_check = False
        config.os_detect = False

    # Stealth overrides
    if config.stealth:
        if config.timing == TimingProfile.NORMAL:
            config.timing = TimingProfile.SNEAKY
        config.randomize_ports = True
        if ScanType.CONNECT in config.scan_types:
            config.scan_types = [ScanType.SYN]

    return config

# Available for all to use it.
