"""
modules/redirect.py
-------------------
Open Redirect detection module.

Injects redirect destination payloads into URL parameters
and checks whether the application follows the injected URL.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

from modules.base import BaseModule
from utils.helpers import extract_params, inject_param


# Payloads targeting common open redirect parameter patterns
DEFAULT_REDIRECT_PAYLOADS = [
    # Direct external URL
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    "///evil.com",
    "////evil.com",
    # Protocol-relative with slashes
    "\\/\\/evil.com",
    "/\\/evil.com",
    "\\/evil.com",
    # URL encoding
    "https%3A%2F%2Fevil.com",
    "%2F%2Fevil.com",
    "%5C%2Fevil.com",
    # Unicode / homograph
    "https://evil.com%23",
    "https://evil.com%3F",
    # Null byte
    "https://evil.com%00.trusted.com",
    # Whitelisted domain bypass
    "https://evil.com?trusted.com",
    "https://evil.com#trusted.com",
    "https://trusted.evil.com",
    # Double slash
    "https://evil.com//trusted.com",
    # Data URI
    "data:text/html,<script>alert(1)</script>",
    # JavaScript URI
    "javascript:alert(1)",
    # Relative path confusion
    "/https://evil.com",
    "/%09/evil.com",
    "/%2F%2Fevil.com",
]

REDIRECT_TARGET = "evil.com"  # marker to check in Location header


class OpenRedirectModule(BaseModule):
    """
    Open Redirect detection module.

    Injects redirect payloads into URL parameters and checks:
    1. Location header for injected domain
    2. 301/302/303/307/308 status with injected URL
    3. Meta-refresh tags in response body
    """

    def load_payloads(self) -> List[str]:
        if self.config.wordlist:
            return self._load_external_wordlist(self.config.wordlist)
        return DEFAULT_REDIRECT_PAYLOADS

    def execute(self) -> List[Dict[str, Any]]:
        payloads = self.load_payloads()
        self.logger.info(f"[+] {len(payloads)} Open Redirect payloads loaded")

        params = extract_params(self.config.url, self.config.param)
        if not params:
            self.logger.warning("[!] No injectable parameters found in URL")
            return []

        self.logger.info(f"[+] Parameters: {', '.join(params)}")

        jobs = [(p, param) for param in params for p in payloads]
        self.logger.info(f"[*] Testing {len(jobs)} combinations...")

        results = []
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {
                executor.submit(self._test_payload, payload, param): (payload, param)
                for payload, param in jobs
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    if result.get("vulnerable"):
                        self.logger.info(
                            f"  [VULN] Param='{result['param']}'  "
                            f"Payload='{result['payload'][:50]}'  "
                            f"| {result['evidence']}"
                        )

        return results

    def _test_payload(self, payload: str, param: str) -> Dict[str, Any]:
        """Inject payload without following redirects so we can inspect Location. Delay per-worker."""
        if self.config.delay:
            time.sleep(self.config.delay)

        injected_url = inject_param(self.config.url, param, payload)
        response = self.http.get(injected_url, allow_redirects=False)

        if response is None:
            return {
                "payload": payload, "param": param,
                "vulnerable": False, "evidence": "No response", "url": injected_url,
            }

        return self.analyze_response(response, payload, param)

    def analyze_response(self, response, payload: str, param: str, **kwargs) -> Dict[str, Any]:
        """
        Detect open redirect via:
        1. Location header containing the injected domain
        2. Meta-refresh tag in body with injected domain
        3. JavaScript window.location assignment
        """
        result = {
            "payload": payload, "param": param, "vulnerable": False,
            "evidence": "", "status_code": response.status_code,
            "response_length": len(response.content),
            "url": response.url if hasattr(response, "url") else self.config.url,
        }

        # Check 1: Location header redirect
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location", "")
            if REDIRECT_TARGET in location:
                result["vulnerable"] = True
                result["evidence"] = f"Redirects to injected URL via Location: {location}"
                return result

        body = response.text.lower()

        # Check 2: Meta-refresh
        if "meta" in body and "refresh" in body and REDIRECT_TARGET in body:
            result["vulnerable"] = True
            result["evidence"] = "Meta-refresh tag pointing to injected domain"
            return result

        # Check 3: JavaScript redirect
        for pattern in ["window.location", "location.href", "location.replace"]:
            if pattern in body and REDIRECT_TARGET in body:
                result["vulnerable"] = True
                result["evidence"] = f"JavaScript redirect ({pattern}) to injected domain"
                return result

        return result
