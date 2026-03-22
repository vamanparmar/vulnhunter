"""
core/engine.py
--------------
Main scan engine. Orchestrates probe → WAF detect → fingerprint → scan → report.
"""

import json
import time
import csv
from datetime import datetime
from typing import List, Dict, Any

from core.config import Config
from core.module_loader import load_module
from core.waf import WAFDetector
from core.banner import (
    print_banner, print_section, print_step, print_warn,
    print_error, print_success, print_summary_table, print_finding, Color
)
from utils.logger import get_logger
from utils.request_handler import RequestHandler
from utils.fingerprint import fingerprint_target


class Engine:
    """
    Core scan engine.

    Pipeline:
        1. Print banner
        2. Probe target reachability
        3. WAF detection
        4. Target fingerprinting
        5. Load and execute exploit module
        6. Aggregate results
        7. Write output report
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = get_logger()
        self.http = RequestHandler(config)
        self.results: List[Dict[str, Any]] = []
        self.start_time: float = 0.0
        self._nc = config.no_color   # shorthand

    def run(self) -> None:
        """Execute the full scan pipeline."""
        self.start_time = time.time()

        if not self.config.silent:
            print_section("SCAN CONFIGURATION", no_color=self._nc)
            print_step(f"Target      : {self.config.url}", no_color=self._nc)
            print_step(f"Module      : {self.config.module.upper()}", no_color=self._nc)
            print_step(f"Threads     : {self.config.threads}", no_color=self._nc)
            print_step(f"Timeout     : {self.config.timeout}s", no_color=self._nc)
            print_step(f"Delay       : {self.config.delay}s", no_color=self._nc)
            print_step(f"Dry Run     : {self.config.dry_run}", no_color=self._nc)
            if self.config.proxy:
                print_step(f"Proxy       : {self.config.proxy}", no_color=self._nc)
            if self.config.wordlist:
                print_step(f"Wordlist    : {self.config.wordlist}", no_color=self._nc)
            if self.config.output:
                print_step(f"Output      : {self.config.output} [{self.config.output_format}]", no_color=self._nc)

        # Step 1: Probe (store response for reuse)
        probe_resp = self._probe_target()
        if probe_resp is None:
            return

        # Step 2: WAF
        self._detect_waf()

        # Step 3: Fingerprint (reuse probe response — no extra request)
        self._fingerprint(probe_resp)

        if self.config.dry_run:
            print_section("DRY RUN MODE", no_color=self._nc)
            self._dry_run_summary()
            return

        # Step 4: Scan
        print_section(f"RUNNING MODULE: {self.config.module.upper()}", no_color=self._nc)
        self._run_module()

        # Step 5: Output
        if self.config.output:
            self._save_output()

        # Step 6: Summary
        elapsed = time.time() - self.start_time
        print_summary_table(self.results, elapsed, no_color=self._nc)

    # ------------------------------------------------------------------ #
    #  Pipeline steps                                                       #
    # ------------------------------------------------------------------ #

    def _probe_target(self):
        """Confirm target is reachable. Returns the response on success, None on failure."""
        print_section("PROBING TARGET", no_color=self._nc)
        print_step("Sending baseline request...", no_color=self._nc)
        resp = self.http.get(self.config.url)
        if resp is None:
            print_error(
                "Target is unreachable. Check URL, network, and proxy settings.",
                no_color=self._nc
            )
            return None
        print_success(
            f"Target alive  HTTP {resp.status_code}  "
            f"({len(resp.content):,} bytes)  "
            f"{resp.elapsed.total_seconds():.3f}s",
            no_color=self._nc
        )
        return resp

    def _detect_waf(self) -> None:
        """Run WAF heuristics and report findings."""
        print_section("WAF DETECTION", no_color=self._nc)
        print_step("Sending WAF probe payload...", no_color=self._nc)
        detector = WAFDetector(self.http, self.config.url)
        waf_name = detector.detect()
        if waf_name:
            print_warn(f"WAF Detected: {waf_name}  — payloads may be filtered", no_color=self._nc)
        else:
            print_success("No WAF fingerprint detected", no_color=self._nc)

    def _fingerprint(self, resp=None) -> None:
        """Extract and display server/framework fingerprint from the probe response."""
        print_section("TARGET FINGERPRINT", no_color=self._nc)
        if resp:
            info = fingerprint_target(resp)
            for key, value in info.items():
                if value:
                    print_step(f"{key:<24}: {value}", no_color=self._nc)
        else:
            print_warn("Could not retrieve fingerprint", no_color=self._nc)

    def _run_module(self) -> None:
        """Dynamically load and execute the selected exploit module."""
        module_class = load_module(self.config.module)
        if module_class is None:
            print_error(f"Module '{self.config.module}' not found.", no_color=self._nc)
            return

        instance = module_class(self.config, self.http)
        self.results = instance.execute()

    def _dry_run_summary(self) -> None:
        """Show scan plan without executing payloads."""
        module_class = load_module(self.config.module)
        if module_class is None:
            print_error(f"Module '{self.config.module}' not found.", no_color=self._nc)
            return
        instance  = module_class(self.config, self.http)
        payloads  = instance.load_payloads()
        print_step(f"Module     : {self.config.module.upper()}", no_color=self._nc)
        print_step(f"Payloads   : {len(payloads)} loaded", no_color=self._nc)
        print_step(f"Target URL : {self.config.url}", no_color=self._nc)
        print_warn("No requests were sent.", no_color=self._nc)

    # ------------------------------------------------------------------ #
    #  Output                                                               #
    # ------------------------------------------------------------------ #

    def _save_output(self) -> None:
        """Save results to file in the configured format."""
        fmt = self.config.output_format.lower()
        try:
            if fmt == "json":
                self._write_json()
            elif fmt == "csv":
                self._write_csv()
            else:
                self._write_txt()
            print_success(
                f"Report saved → {self.config.output}  [{fmt.upper()}]",
                no_color=self._nc
            )
        except OSError as e:
            print_error(f"Failed to save report: {e}", no_color=self._nc)

    def _write_json(self) -> None:
        report = {
            "meta": {
                "tool": "VulnHunter",
                "version": "3.0.0",
                "target": self.config.url,
                "module": self.config.module,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "duration_seconds": round(time.time() - self.start_time, 2),
                "config": {
                    "threads": self.config.threads,
                    "timeout": self.config.timeout,
                    "proxy": self.config.proxy,
                    "delay": self.config.delay,
                    "wordlist": self.config.wordlist,
                },
            },
            "summary": {
                "total_tested":          len(self.results),
                "vulnerabilities_found": len([r for r in self.results if r.get("vulnerable")]),
            },
            "findings": [r for r in self.results if r.get("vulnerable")],
            "all_results": self.results,
        }
        with open(self.config.output, "w") as f:
            json.dump(report, f, indent=2, default=str)

    def _write_csv(self) -> None:
        fieldnames = ["vulnerable", "param", "payload", "evidence", "status_code", "response_length", "url"]
        with open(self.config.output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(self.results)

    def _write_txt(self) -> None:
        hits = [r for r in self.results if r.get("vulnerable")]
        with open(self.config.output, "w") as f:
            f.write(f"VulnHunter Scan Report\n")
            f.write(f"Target  : {self.config.url}\n")
            f.write(f"Module  : {self.config.module}\n")
            f.write(f"Time    : {datetime.utcnow().isoformat()}Z\n")
            f.write(f"Results : {len(hits)} vulnerabilities from {len(self.results)} tests\n\n")
            for i, hit in enumerate(hits, 1):
                f.write(f"[{i}] param={hit.get('param')}  payload={hit.get('payload')}\n")
                f.write(f"    evidence : {hit.get('evidence')}\n")
                f.write(f"    url      : {hit.get('url')}\n\n")
