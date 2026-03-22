"""
modules/base.py
---------------
Abstract base class for all exploit modules.
All modules MUST inherit from BaseModule and implement the required methods.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any

from core.config import Config
from utils.request_handler import RequestHandler
from utils.logger import get_logger


class BaseModule(ABC):
    """
    Abstract base class defining the plugin interface for all exploit modules.

    Every module must implement:
        - load_payloads() -> List[str]
        - execute()       -> List[Dict]
        - analyze_response(response, payload, param) -> Dict
    """

    def __init__(self, config: Config, http: RequestHandler) -> None:
        self.config = config
        self.http = http
        self.logger = get_logger()
        self.findings: List[Dict[str, Any]] = []

    @abstractmethod
    def load_payloads(self) -> List[str]:
        """
        Load payloads for this module.

        Returns:
            A list of payload strings.
        """
        ...

    @abstractmethod
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the exploit scan.

        Returns:
            A list of result dictionaries with at minimum:
            {
                "payload": str,
                "vulnerable": bool,
                "param": str,
                "evidence": str,
                "url": str
            }
        """
        ...

    @abstractmethod
    def analyze_response(self, response, payload: str, param: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze an HTTP response to determine if a payload triggered a vulnerability.

        Args:
            response: The HTTP response object.
            payload: The payload that was sent.
            param: The parameter the payload was injected into.
            **kwargs: Additional context (e.g. baseline) passed by subclasses.

        Returns:
            A result dictionary.
        """
        ...

    def _load_external_wordlist(self, path: str) -> List[str]:
        """
        Load payloads from an external file (one per line).

        Args:
            path: File path to the wordlist.

        Returns:
            List of payloads.
        """
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            self.logger.info(f"[+] Loaded {len(lines)} payloads from {path}")
            return lines
        except FileNotFoundError:
            self.logger.error(f"Wordlist not found: {path}")
            return []
        except OSError as e:
            self.logger.error(f"Failed to read wordlist: {e}")
            return []
