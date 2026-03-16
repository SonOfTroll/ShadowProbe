"""
ShadowProbe entry point for ``python -m shadowprobe``.
"""

import sys

from shadowprobe.cli import parse_args
from shadowprobe.orchestrator import ScanOrchestrator
from shadowprobe.utils.logger import get_logger, print_banner


def main() -> None:
    """Main entry point."""
    config = parse_args()
    logger = get_logger("shadowprobe", verbosity=config.verbosity)
    print_banner()

    orch = ScanOrchestrator(config, logger=logger)
    command_str = " ".join(sys.argv)
    orch.run(command_str=command_str)
    output = orch.generate_report()

    # Print to stdout if no output file specified
    if not config.output_file:
        print(output)


if __name__ == "__main__":
    main()

# Available for all to use it.
