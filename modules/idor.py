"""
modules/idor.py
---------------
Insecure Direct Object Reference (IDOR) detection module.

Detects IDOR by:
- Iterating numeric/UUID object IDs in URL parameters
- Comparing responses to detect unauthorized data access
- Flagging when different IDs return identical or suspiciously rich responses
"""

import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Tuple

from modules.base import BaseModule
from utils.helpers import extract_params, inject_param


# Patterns that suggest sensitive data was returned
SENSITIVE_DATA_PATTERNS = [
    # PII
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # email
    r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b',                      # SSN
    r'\b(?:\d[ -]*?){13,16}\b',                                 # credit card
    r'\b\d{10,15}\b',                                           # phone number
    # Auth tokens
    r'["\']?token["\']?\s*[:=]\s*["\']?[A-Za-z0-9\-_\.]{20,}',
    r'["\']?password["\']?\s*[:=]\s*["\']?.{4,}["\']?',
    r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{16,}',
    r'["\']?secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{10,}',
    # Data fields
    r'["\']?address["\']?\s*[:=]',
    r'["\']?phone["\']?\s*[:=]',
    r'["\']?dob["\']?\s*[:=]',
    r'["\']?ssn["\']?\s*[:=]',
    r'["\']?balance["\']?\s*[:=]',
    r'["\']?account[_-]?number["\']?\s*[:=]',
]

# HTTP methods to test for IDOR
IDOR_METHODS = ["GET"]


class IDORModule(BaseModule):
    """
    IDOR detection module.

    Strategy:
    1. Enumerate a range of numeric IDs in each URL parameter
    2. Also test UUID-style IDs if present
    3. Compare response content between IDs to detect data leakage
    4. Scan responses for sensitive data patterns (PII, tokens, secrets)
    5. Detect horizontal privilege escalation by comparing content variation

    Example targets:
        http://target.lab/api/user?id=1
        http://target.lab/invoice?ref=100
        http://target.lab/document?uuid=a1b2c3d4-...
    """

    def __init__(self, config, http) -> None:
        super().__init__(config, http)
        # Allow seed/range to be overridden via config.param or wordlist;
        # default values are sensible for most targets.
        self.SEED_ID = 1
        self.ENUM_RANGE = 10

    def load_payloads(self) -> List[str]:
        """
        Generate a list of ID payloads to test.

        Returns numeric IDs plus a sample of UUID-style values.
        """
        if self.config.wordlist:
            return self._load_external_wordlist(self.config.wordlist)

        payloads = []

        # Numeric range around seed
        for i in range(self.SEED_ID, self.SEED_ID + self.ENUM_RANGE):
            payloads.append(str(i))

        # Negative and boundary values
        payloads += ["0", "-1", "99999", "100000", "999999"]

        # Random UUIDs (common in modern APIs)
        for _ in range(5):
            payloads.append(str(uuid.uuid4()))

        # Common admin/privileged IDs
        payloads += ["admin", "root", "superuser", "1337", "0001"]

        return payloads

    def execute(self) -> List[Dict[str, Any]]:
        """
        Enumerate IDs across detected parameters and detect IDOR.

        Returns:
            List of result dicts.
        """
        payloads = self.load_payloads()
        self.logger.info(f"[+] {len(payloads)} IDOR ID payloads generated")

        params = extract_params(self.config.url, self.config.param)
        if not params:
            self.logger.warning("[!] No injectable parameters detected in URL")
            self.logger.warning("    Try: --url 'http://target.lab/api/user?id=1' --param id")
            return []

        self.logger.info(f"[+] Parameters: {', '.join(params)}")

        # Baseline: the original response for each param's current value
        baselines = self._take_baselines(params)

        jobs: List[Tuple[str, str]] = [
            (payload, param)
            for param in params
            for payload in payloads
        ]
        self.logger.info(f"[*] Enumerating {len(jobs)} ID/param combinations...")

        results = []
        responses_by_param: Dict[str, List[str]] = {p: [] for p in params}

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {
                executor.submit(
                    self._test_payload, payload, param, baselines.get(param)
                ): (payload, param)
                for payload, param in jobs
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    if result.get("body_snapshot"):
                        responses_by_param[result["param"]].append(
                            result.pop("body_snapshot")
                        )
                    if result.get("vulnerable"):
                        self.logger.info(
                            f"  [VULN] Param='{result['param']}'  "
                            f"ID='{result['payload']}'  "
                            f"| {result['evidence']}"
                        )

        # Post-scan: check for suspiciously uniform responses (same body for all IDs)
        for param, bodies in responses_by_param.items():
            if len(bodies) > 3:
                unique_bodies = len(set(bodies))
                if unique_bodies == 1:
                    self.logger.warning(
                        f"  [!] Param '{param}': all IDs returned identical responses "
                        f"— possible no auth enforcement or static page"
                    )

        return results

    def _take_baselines(self, params: List[str]) -> Dict[str, Dict]:
        """Capture baseline responses with the original parameter value."""
        baselines: Dict[str, Dict] = {}
        for param in params:
            resp = self.http.get(self.config.url)
            if resp:
                baselines[param] = {
                    "status": resp.status_code,
                    "length": len(resp.content),
                    "body": resp.text,
                }
        return baselines

    def _test_payload(
        self, payload: str, param: str, baseline: Dict
    ) -> Dict[str, Any]:
        """Inject an ID payload and analyze for IDOR indicators. Delay applied per-worker."""
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

        return self.analyze_response(response, payload, param, baseline)

    def analyze_response(
        self,
        response,
        payload: str,
        param: str,
        baseline: Dict = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Detect IDOR indicators:

        1. Sensitive data patterns in response body (PII, tokens, secrets)
        2. HTTP 200 with non-trivial content for IDs that shouldn't exist
        3. Response significantly different from baseline (data from another object)
        4. 403→200 transition (access control bypass by changing ID)
        """
        result: Dict[str, Any] = {
            "payload": payload,
            "param": param,
            "vulnerable": False,
            "evidence": "",
            "status_code": response.status_code,
            "response_length": len(response.content),
            "url": response.url if hasattr(response, "url") else self.config.url,
            "body_snapshot": response.text[:200] if response.text else "",
        }

        body = response.text

        # Check 1: Sensitive data patterns
        for pattern in SENSITIVE_DATA_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                result["vulnerable"] = True
                result["evidence"] = (
                    f"Sensitive data pattern matched: '{pattern[:40]}' "
                    f"— snippet: '{match.group()[:60]}'"
                )
                return result

        # Check 2: Baseline comparison — significantly different response
        if baseline:
            bl_len = baseline.get("length", 0)
            bl_status = baseline.get("status", 0)

            # Status code flip: e.g. was 403, now 200 → access control bypassed
            if bl_status in (403, 401) and response.status_code == 200:
                result["vulnerable"] = True
                result["evidence"] = (
                    f"Status flip: {bl_status} → 200 for ID '{payload}' "
                    f"— possible access control bypass"
                )
                return result

            # Large length delta: different object returned
            if bl_len > 0:
                delta = abs(len(response.content) - bl_len) / bl_len
                if delta > 0.25 and response.status_code == 200 and len(response.content) > 100:
                    result["vulnerable"] = True
                    result["evidence"] = (
                        f"Response length delta {delta:.0%} for ID '{payload}' "
                        f"(baseline={bl_len}B, injected={len(response.content)}B) "
                        f"— possible different object returned"
                    )
                    return result

        # Check 3: 200 OK with non-trivial JSON-like body for a random ID
        if (
            response.status_code == 200
            and len(response.content) > 50
            and any(c in body for c in ["{", "[", "<"])
            and payload not in ["0", "-1"]  # don't flag obvious invalid IDs
        ):
            # Only flag if baseline was not also 200 with same size
            if baseline and baseline.get("status") != 200:
                result["vulnerable"] = True
                result["evidence"] = (
                    f"HTTP 200 with structured response for ID '{payload}' "
                    f"— baseline returned {baseline.get('status')}"
                )

        return result
