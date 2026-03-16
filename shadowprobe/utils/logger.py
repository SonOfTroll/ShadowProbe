"""
Colored logging utility for ShadowProbe.

Provides a configured logger with rich-formatted console output
and optional file logging.
"""

import logging
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# ── Custom theme ────────────────────────────────────────────────────────
_THEME = Theme({
    "info":     "cyan",
    "warning":  "yellow bold",
    "error":    "red bold",
    "critical": "white on red bold",
    "success":  "green bold",
    "dim":      "dim white",
})

console = Console(theme=_THEME, stderr=True)


def get_logger(
    name: str = "shadowprobe",
    verbosity: int = 0,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Return a configured logger instance.

    Args:
        name:      Logger name (usually module ``__name__``).
        verbosity: 0 = WARNING, 1 = INFO, 2+ = DEBUG.
        log_file:  Optional path to write logs to disk.

    Returns:
        A ``logging.Logger`` ready for use.
    """
    level_map = {0: logging.WARNING, 1: logging.INFO}
    level = level_map.get(verbosity, logging.DEBUG)

    logger = logging.getLogger(name)

    # Avoid duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    # ── Rich console handler ────────────────────────────────────────
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
        tracebacks_show_locals=verbosity >= 2,
    )
    rich_handler.setLevel(level)
    logger.addHandler(rich_handler)

    # ── File handler (optional) ─────────────────────────────────────
    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(str(path), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


def print_banner() -> None:
    """Print the ShadowProbe ASCII banner to stderr."""
    banner = r"""
[bold cyan]
  ____  _               _                ____            _
 / ___|| |__   __ _  __| | _____      __/ _  \ _ __ ___ | |__   ___
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / |_) | '__/ _ \| '_ \ / _ \
  ___) | | | | (_| | (_| | (_) \ V  V /|  __/| | | (_) | |_) |  __/
 |____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_|   |_|  \___/|_.__/ \___|
[/bold cyan]
[dim]  ⚡  Advanced Network Reconnaissance & Vulnerability Scanner  v1.0.0[/dim]
[dim]  ⚠  For authorized testing only — use responsibly.[/dim]
"""
    console.print(banner)

# Available for all to use it.
