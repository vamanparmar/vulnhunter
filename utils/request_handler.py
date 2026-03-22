"""
utils/request_handler.py
------------------------
Centralized HTTP request engine.

Provides:
- Session persistence
- Proxy support
- Retry logic with exponential backoff
- Timeout handling
- Custom headers and cookies
- Thread-safe request execution
"""

import time
import threading
from typing import Optional, Dict, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

from core.config import Config
from utils.logger import get_logger

# Suppress SSL warnings for lab environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


class RequestHandler:
    """
    Thread-safe centralized HTTP request handler.

    All modules use this class to send requests, ensuring consistent
    headers, proxy, timeout, retry, and session handling.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = get_logger()
        self._lock = threading.Lock()
        self._session = self._build_session()

    def _build_session(self) -> requests.Session:
        """Build and configure a requests Session with retry policy."""
        session = requests.Session()

        # Retry strategy: retry on connection errors and 5xx
        retry_strategy = Retry(
            total=self.config.retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Base headers
        session.headers.update({
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })

        # Custom headers from CLI
        if self.config.headers:
            session.headers.update(self.config.headers)

        # Cookies from CLI
        if self.config.cookies:
            session.cookies.update(self.config.cookies)

        # Proxy config
        if self.config.proxy:
            session.proxies = self.config.proxy_dict()
            self.logger.debug(f"Proxy configured: {self.config.proxy}")

        return session

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        allow_redirects: bool = True,
    ) -> Optional[requests.Response]:
        """
        Send a GET request.

        Args:
            url: Target URL.
            params: Optional query parameters dict.
            allow_redirects: Follow redirects.

        Returns:
            Response object or None on failure.
        """
        return self._send("GET", url, params=params, allow_redirects=allow_redirects)

    def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        allow_redirects: bool = False,
    ) -> Optional[requests.Response]:
        """
        Send a POST request.

        Args:
            url: Target URL.
            data: Form data dict.
            json_body: JSON payload dict.
            allow_redirects: Follow redirects (default False for login detection).

        Returns:
            Response object or None on failure.
        """
        return self._send(
            "POST", url, data=data, json=json_body, allow_redirects=allow_redirects
        )

    def put(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Optional[requests.Response]:
        """Send a PUT request."""
        return self._send("PUT", url, data=data)

    def _send(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Internal method to send any HTTP request with error handling.

        requests.Session is thread-safe for concurrent sends — no lock needed here.
        The lock is reserved for session-level mutation (e.g. updating cookies/headers).
        """
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("verify", False)  # Allow self-signed certs in lab

        try:
            response = self._session.request(method, url, **kwargs)

            self.logger.debug(
                f"{method} {url[:80]} → HTTP {response.status_code} "
                f"({len(response.content)} bytes)"
            )
            return response

        except requests.exceptions.ProxyError as e:
            self.logger.error(f"Proxy error: {e}")
        except requests.exceptions.SSLError as e:
            self.logger.debug(f"SSL error (ignored in lab mode): {e}")
            kwargs["verify"] = False
            try:
                return self._session.request(method, url, **kwargs)
            except Exception:
                pass
        except requests.exceptions.ConnectionError as e:
            self.logger.debug(f"Connection error: {url[:60]} — {e}")
        except requests.exceptions.Timeout:
            self.logger.debug(f"Request timed out: {url[:60]}")
        except requests.exceptions.TooManyRedirects:
            self.logger.debug(f"Too many redirects: {url[:60]}")
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Request error: {e}")

        return None

    def update_session_headers(self, headers: dict) -> None:
        """Thread-safe session header update (mutates shared session state)."""
        with self._lock:
            self._session.headers.update(headers)

    def update_session_cookies(self, cookies: dict) -> None:
        """Thread-safe session cookie update (mutates shared session state)."""
        with self._lock:
            self._session.cookies.update(cookies)
