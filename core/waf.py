"""
core/waf.py
-----------
WAF (Web Application Firewall) detection heuristics.
Sends a known malicious probe and inspects the response for WAF signatures.
"""

from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.logger import get_logger


# WAF signatures: maps WAF name to list of (header_key, header_value_substring) or body_substring
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": [("cf-ray", ""), ("server", "cloudflare")],
        "body": ["Attention Required! | Cloudflare", "cloudflare-nginx"],
        "status": [403],
    },
    "AWS WAF": {
        "headers": [("x-amzn-requestid", ""), ("x-amz-cf-id", "")],
        "body": ["AWS WAF", "Request blocked"],
        "status": [403],
    },
    "Akamai": {
        "headers": [("x-check-cacheable", ""), ("akamai", ""), ("x-akamai-transformed", "")],
        "body": ["Access Denied - Akamai", "AkamaiGHost", "The requested URL was rejected. Please consult with your administrator."],
        "status": [403],
    },
    "ModSecurity": {
        "headers": [("server", "mod_security"), ("server", "modsecurity")],
        "body": ["ModSecurity", "Not Acceptable!", "406 Not Acceptable"],
        "status": [406, 501],
    },
    "Sucuri": {
        "headers": [("x-sucuri-id", ""), ("server", "sucuri")],
        "body": ["Access Denied - Sucuri Website Firewall"],
        "status": [403],
    },
    "Imperva / Incapsula": {
        "headers": [("x-iinfo", ""), ("set-cookie", "incap_ses")],
        "body": ["Incapsula incident", "Request unsuccessful"],
        "status": [403],
    },
    "F5 BIG-IP ASM": {
        "headers": [("x-cnection", ""), ("set-cookie", "ts")],
        "body": ["The requested URL was rejected", "Please consult with your administrator"],
        "status": [403],
    },
}

# Probe payload known to trigger most WAFs
WAF_PROBE_PAYLOAD = "<script>alert(1)</script>"
WAF_PROBE_PARAM   = "vulnhunter_waf_probe"


class WAFDetector:
    """
    Heuristic WAF detection using a probe payload and response inspection.

    Compares response headers, body, and status codes against known WAF signatures.
    """

    def __init__(self, http, base_url: str) -> None:
        self.http = http
        self.base_url = base_url
        self.logger = get_logger()

    def detect(self) -> Optional[str]:
        """
        Send a WAF probe and analyze the response.

        Builds the probe URL safely so existing query parameters are preserved
        and the probe param is appended correctly.

        Returns:
            WAF name if detected, None otherwise.
        """
        parsed = urlparse(self.base_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[WAF_PROBE_PARAM] = [WAF_PROBE_PAYLOAD]
        probe_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

        response = self.http.get(probe_url)

        if response is None:
            self.logger.debug("WAF probe got no response — network issue or target unreachable")
            return None  # Inconclusive; do not assert a WAF is present

        return self._analyze_response(response)

    def _analyze_response(self, response) -> Optional[str]:
        """Match response against WAF signatures."""
        resp_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        resp_body = response.text.lower()
        resp_status = response.status_code

        for waf_name, signatures in WAF_SIGNATURES.items():
            # Check headers
            for header_key, header_val in signatures.get("headers", []):
                hk = header_key.lower()
                if hk in resp_headers:
                    if not header_val or header_val.lower() in resp_headers[hk]:
                        self.logger.debug(f"WAF match via header '{header_key}': {waf_name}")
                        return waf_name

            # Check body keywords
            for keyword in signatures.get("body", []):
                if keyword.lower() in resp_body:
                    self.logger.debug(f"WAF match via body keyword '{keyword}': {waf_name}")
                    return waf_name

            # Status code check: only fire if no header OR body match was found above,
            # AND the body also contains at least one WAF-specific body keyword.
            # This prevents a generic 403 from matching the wrong WAF.
            if resp_status in signatures.get("status", []):
                waf_body_keys = [k.lower() for k in signatures.get("body", [])]
                if waf_body_keys and any(k in resp_body for k in waf_body_keys):
                    self.logger.debug(f"WAF match via status+body {resp_status}: {waf_name}")
                    return waf_name

        return None
