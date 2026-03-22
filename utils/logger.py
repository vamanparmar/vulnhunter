"""
utils/logger.py
---------------
Structured logging setup for VulnHunter.

Provides:
- Color-coded terminal output (INFO/DEBUG/WARNING/ERROR)
- Centralized logger instance via get_logger()
- setup_logger() to configure at startup
"""

import logging
import sys
from typing import Optional


# ANSI color codes
class Colors:
    RESET = "\033[0m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    GREY = "\033[90m"
    BOLD = "\033[1m"


_logger: Optional[logging.Logger] = None


class ColorFormatter(logging.Formatter):
    """
    Custom formatter that applies ANSI colors based on log level.
    """

    LEVEL_COLORS = {
        logging.DEBUG: Colors.GREY,
        logging.INFO: Colors.RESET,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.RED + Colors.BOLD,
    }

    def __init__(self, no_color: bool = False) -> None:
        super().__init__()
        self.no_color = no_color

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()

        if self.no_color:
            return msg

        color = self.LEVEL_COLORS.get(record.levelno, Colors.RESET)
        return f"{color}{msg}{Colors.RESET}"


def setup_logger(verbose: bool = False, no_color: bool = False) -> None:
    """
    Configure the global VulnHunter logger.

    Args:
        verbose: If True, show DEBUG level messages.
        no_color: If True, disable ANSI color codes.
    """
    global _logger

    level = logging.DEBUG if verbose else logging.INFO

    logger = logging.getLogger("vulnhunter")
    logger.setLevel(level)
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(ColorFormatter(no_color=no_color))

    logger.addHandler(handler)
    logger.propagate = False

    _logger = logger


def get_logger() -> logging.Logger:
    """
    Retrieve the global logger instance.

    Returns:
        Logger — creates a default one if not yet initialized.
    """
    global _logger
    if _logger is None:
        setup_logger()
    return _logger
