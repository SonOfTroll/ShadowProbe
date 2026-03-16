"""
Abstract base reporter for ShadowProbe output generation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from shadowprobe.core.config import ScanReport


class BaseReporter(ABC):
    """Base class for all report generators."""

    @abstractmethod
    def generate(self, report: ScanReport, output_path: Optional[str] = None) -> str:
        """Generate a report from a ScanReport.

        Args:
            report:      The completed scan report.
            output_path: File path to write to. If None, return as string.

        Returns:
            The generated report content as a string.
        """

# Available for all to use it.
