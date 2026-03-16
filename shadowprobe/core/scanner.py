"""
Abstract base scanner for ShadowProbe modules.

Every scanner module (discovery, portscan, fingerprint) inherits from
``BaseScanner`` and implements ``scan()``.
"""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from typing import Any, List, Optional

from shadowprobe.core.config import ScanConfig
from shadowprobe.utils.network import apply_jitter


class BaseScanner(ABC):
    """Abstract base class for all scanner modules."""

    def __init__(self, config: ScanConfig, logger: Optional[logging.Logger] = None):
        self.config = config
        self.log = logger or logging.getLogger(self.__class__.__name__)
        self._results: List[Any] = []
        self._lock = threading.Lock()
        self._start_time: float = 0.0
        self._end_time: float = 0.0

    # ── Public Interface ────────────────────────────────────────────
    @abstractmethod
    def scan(self, targets: List[str], **kwargs: Any) -> List[Any]:
        """Run the scan on the given targets. Must be overridden."""

    def validate(self) -> bool:
        """Optional pre-flight check (e.g. root required for SYN scan).

        Returns True if prerequisites are satisfied.
        """
        return True

    def get_results(self) -> List[Any]:
        """Return collected results (thread-safe)."""
        with self._lock:
            return list(self._results)

    # ── Helpers ─────────────────────────────────────────────────────
    def _add_result(self, result: Any) -> None:
        """Thread-safe result collection."""
        with self._lock:
            self._results.append(result)

    def _delay(self) -> None:
        """Sleep according to the configured timing profile + jitter."""
        base = self.config.effective_delay()
        if base > 0:
            time.sleep(apply_jitter(base))

    @property
    def duration(self) -> float:
        if self._end_time:
            return self._end_time - self._start_time
        return time.time() - self._start_time

    def _start_timer(self) -> None:
        self._start_time = time.time()

    def _stop_timer(self) -> None:
        self._end_time = time.time()

# Available for all to use it.
