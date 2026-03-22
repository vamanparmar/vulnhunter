<div align="center">

```
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

**Modular Web Exploitation Framework** · Codename: *RedSight* · `v3.0.0`

<br/>

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Version](https://img.shields.io/badge/Version-3.0.0-E74C3C?style=flat-square)](https://github.com/vulnhunter/vulnhunter/releases)
[![License](https://img.shields.io/badge/License-MIT-95A5A6?style=flat-square)](LICENSE)
[![Modules](https://img.shields.io/badge/Modules-8-E67E22?style=flat-square)](#modules)
[![Tests](https://img.shields.io/badge/Tests-50%2B-27AE60?style=flat-square)](#running-tests)
[![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-C0392B?style=flat-square)](#legal-disclaimer)

</div>

---

> [!WARNING]
> **VulnHunter is strictly for authorized penetration testing, CTF challenges, and security research on systems you own or have explicit written permission to test. Unauthorized use against systems you do not own is illegal and unethical. The authors accept no liability for misuse.**

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Modules](#modules)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [All Modules](#all-modules)
  - [Output & Reporting](#output--reporting)
  - [Advanced Options](#advanced-options)
  - [YAML Profiles](#yaml-profiles)
- [CLI Reference](#cli-reference)
- [Output Formats](#output-formats)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Writing a Custom Module](#writing-a-custom-module)
- [Authorized Practice Targets](#authorized-practice-targets)
- [Contributing](#contributing)
- [Legal Disclaimer](#legal-disclaimer)
- [License](#license)

---

## Overview

VulnHunter is a **modular, multi-threaded web vulnerability scanner** written in Python. Built around a clean plugin architecture, each vulnerability class is an independent module that can be loaded, replaced, or extended without touching the core engine.

Designed for:
- **CTF players** who need fast, reliable scanning during competitions
- **Penetration testers** working on authorized lab environments
- **Security students** learning how web vulnerabilities are detected in practice

The scanner covers the most common OWASP Top 10 vulnerability classes with both active detection (error-based, output-based) and blind detection (time-based, differential analysis).

---

## Features

| Feature | Details |
|---|---|
| 🔌 **Plugin Architecture** | 8 built-in modules — add new ones with a single file and one registry entry |
| 🛡️ **WAF Detection** | Fingerprints Cloudflare, AWS WAF, Akamai, ModSecurity, Sucuri, Imperva, F5 BIG-IP |
| 🔍 **Target Fingerprinting** | Detects server, framework, CMS, missing security headers, and cookie flag issues |
| 🧵 **Multi-threading** | Configurable thread pool with per-worker rate limiting via `--delay` |
| 🌐 **Proxy Support** | Full Burp Suite / OWASP ZAP / MITM proxy integration |
| ⚙️ **YAML Profiles** | Save and reuse scan configurations; override any field from the CLI |
| 📊 **Multi-format Reports** | JSON, CSV, and plain-text output with full finding metadata |
| 🔒 **SSL/TLS** | Handles self-signed certificates in lab environments automatically |
| 🔁 **Retry Logic** | Exponential backoff on connection errors and 5xx responses |
| ✅ **Test Suite** | 50+ pytest unit tests across all modules and utilities |

---

## Modules

| Module | Flag | Techniques |
|---|---|---|
| SQL Injection | `--module sqli` | Error-based, boolean blind, differential response analysis |
| Cross-Site Scripting | `--module xss` | Reflected XSS — verbatim reflection, HTML-encoding detection |
| Authentication Brute-Force | `--module auth` | Credential stuffing, keyword detection, redirect-based success |
| Local File Inclusion | `--module lfi` | Path traversal, null-byte bypass, PHP wrappers (`php://filter`, `file://`) |
| Server-Side Request Forgery | `--module ssrf` | Loopback, cloud metadata endpoints (AWS/GCP/Azure), protocol wrappers |
| Open Redirect | `--module redirect` | Location header, meta-refresh, JavaScript redirect detection |
| Insecure Direct Object Reference | `--module idor` | Numeric/UUID enumeration, PII pattern matching, access-control bypass |
| OS Command Injection | `--module cmdi` | Output-based (Unix & Windows), time-based blind, error-based |

---

## Installation

**Requirements:** Python 3.8 or higher

```bash
# 1. Clone the repository
git clone https://github.com/vulnhunter/vulnhunter.git
cd vulnhunter

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Install in developer mode with test dependencies
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# Validate your setup without sending any real requests
python main.py --url "http://testphp.vulnweb.com/listproducts.php?cat=1" --module sqli --dry-run

# Run your first SQL injection scan
python main.py --url "http://testphp.vulnweb.com/listproducts.php?cat=1" --module sqli
```

**Expected output:**

```
  ╔══════════════════════════════════════════════════════╗
  ║  Version        v3.0.0  [RedSight]                   ║
  ║  Author         VulnHunter Project                   ║
  ║  Platform       Windows 11                           ║
  ║  Started        2026-03-22 16:53:23                  ║
  ╠══════════════════════════════════════════════════════╣
  ║  ⚠  FOR AUTHORIZED TESTING & CTF USE ONLY           ║
  ╚══════════════════════════════════════════════════════╝

  [*] Target      : http://testphp.vulnweb.com/listproducts.php?cat=1
  [*] Module      : SQLI
  [✔] Target alive  HTTP 200  (4821 bytes)  0.312s
  [✔] No WAF fingerprint detected
  [*] Server                  : Apache/2.4.41
  [*] X-Powered-By            : PHP/8.1.2

  [VULN] Param='cat'  Payload='' OR '1'='1' --'
         evidence: SQL error pattern matched: 'you have an error in your sql syntax'

  ╔══════════════════════════════════════════════╗
  ║               SCAN SUMMARY                   ║
  ╠══════════════════════════════════════════════╣
  ║  Payloads Tested       31                    ║
  ║  Vulnerabilities       3  ← FOUND            ║
  ║  Clean Responses       28                    ║
  ║  Elapsed Time          4.21s                 ║
  ╚══════════════════════════════════════════════╝
```

---

## Usage

### All Modules

```bash
# SQL Injection — error-based, boolean, and differential detection
python main.py --url "http://target.lab/page?id=1" --module sqli

# Cross-Site Scripting — reflected XSS across all URL parameters
python main.py --url "http://target.lab/search?q=1" --module xss

# Local File Inclusion — path traversal and PHP wrapper payloads
python main.py --url "http://target.lab/index.php?page=home" --module lfi --param page

# Authentication Brute-Force — credential stuffing via POST
python main.py --url "http://target.lab/login" --module auth

# Server-Side Request Forgery — loopback and cloud metadata injection
python main.py --url "http://target.lab/fetch?url=http://example.com" --module ssrf --param url

# Open Redirect — Location header and JavaScript redirect detection
python main.py --url "http://target.lab/redirect?next=/" --module redirect --param next

# Insecure Direct Object Reference — ID enumeration and PII detection
python main.py --url "http://target.lab/api/user?id=1" --module idor --param id

# OS Command Injection — output-based and time-based blind
python main.py --url "http://target.lab/ping?host=127.0.0.1" --module cmdi --param host
```

### Output & Reporting

```bash
# Save findings as JSON (default format)
python main.py --url "http://target.lab/?id=1" --module sqli --output report.json

# Save findings as CSV
python main.py --url "http://target.lab/?id=1" --module sqli --output report.csv --output-format csv

# Save findings as plain text
python main.py --url "http://target.lab/?id=1" --module sqli --output report.txt --output-format txt

# Silent mode — suppress all output except confirmed findings
python main.py --url "http://target.lab/?id=1" --module sqli --silent --output findings.json
```

### Advanced Options

```bash
# Route all traffic through Burp Suite for manual inspection
python main.py --url "http://target.lab/?id=1" --module sqli \
  --proxy http://127.0.0.1:8080

# Slow down requests to avoid triggering rate limits (1s delay, 2 threads)
python main.py --url "http://target.lab/?id=1" --module sqli \
  --delay 1.0 --threads 2

# Inject custom headers (e.g. for authenticated scans)
python main.py --url "http://target.lab/?id=1" --module sqli \
  --headers '{"Authorization": "Bearer eyJ..."}'

# Inject session cookies for authenticated scanning
python main.py --url "http://target.lab/?id=1" --module sqli \
  --cookies '{"session": "abc123", "PHPSESSID": "xyz"}'

# Use a custom payload wordlist
python main.py --url "http://target.lab/?id=1" --module sqli \
  --wordlist payloads/sqli.json

# Dry run — count payloads and validate config without sending any requests
python main.py --url "http://target.lab/?id=1" --module sqli --dry-run --verbose

# Disable ANSI colors (useful for piping output to a log file)
python main.py --url "http://target.lab/?id=1" --module sqli --no-color 2>&1 | tee scan.log
```

### YAML Profiles

Save your scan configuration to a YAML file and reuse it across sessions. Any CLI flag overrides the corresponding profile field.

**`profiles/example_ctf.yaml`:**
```yaml
url: http://target.lab/listproducts.php?cat=1
module: sqli
threads: 10
timeout: 15
delay: 0.5
output: output/ctf_sqli.json
output_format: json
verbose: false
```

```bash
# Run from profile
python main.py --profile profiles/example_ctf.yaml

# Override individual fields at runtime
python main.py --profile profiles/example_ctf.yaml --threads 20 --proxy http://127.0.0.1:8080
```

---

## CLI Reference

| Argument | Default | Description |
|---|---|---|
| `--url` | *required* | Target URL — must include `?param=value` for injection modules |
| `--module` | *required* | Vulnerability module to run |
| `--profile` | — | Path to a YAML scan profile |
| **Request Options** | | |
| `--threads` | `5` | Number of concurrent worker threads |
| `--timeout` | `10` | Per-request timeout in seconds |
| `--proxy` | — | HTTP/HTTPS proxy URL (e.g. `http://127.0.0.1:8080`) |
| `--headers` | — | Custom HTTP headers as a JSON string |
| `--cookies` | — | Custom cookies as a JSON string |
| `--delay` | `0.0` | Seconds to wait between requests per worker thread |
| `--retries` | `3` | Max retry attempts per request |
| `--rate-limit` | `0` | Max requests per second (`0` = unlimited) |
| `--user-agent` | — | Custom User-Agent string |
| `--no-redirects` | off | Disable following HTTP redirects |
| **Payload Options** | | |
| `--wordlist` | — | Path to a custom payload file (one payload per line) |
| `--param` | — | Target a specific parameter name (overrides auto-detection) |
| `--encoding` | `none` | Payload encoding: `none`, `url`, `double-url`, `html` |
| **Output Options** | | |
| `--output` | — | File path to save the scan report |
| `--output-format` | `json` | Report format: `json`, `csv`, `txt` |
| `--verbose` | off | Enable debug logging (shows every request and response) |
| `--silent` | off | Suppress all output except confirmed findings |
| `--dry-run` | off | Validate config and count payloads without sending requests |
| `--no-color` | off | Disable ANSI color codes in terminal output |

---

## Output Formats

### JSON

```json
{
  "meta": {
    "tool": "VulnHunter",
    "version": "3.0.0",
    "target": "http://target.lab/?id=1",
    "module": "sqli",
    "timestamp": "2026-03-22T16:53:23Z",
    "duration_seconds": 4.21,
    "config": {
      "threads": 5,
      "timeout": 10,
      "proxy": null,
      "delay": 0.0
    }
  },
  "summary": {
    "total_tested": 31,
    "vulnerabilities_found": 3
  },
  "findings": [
    {
      "param": "id",
      "payload": "' OR '1'='1' --",
      "vulnerable": true,
      "evidence": "SQL error pattern matched: 'you have an error in your sql syntax'",
      "status_code": 200,
      "response_length": 6641,
      "url": "http://target.lab/?id=%27+OR+%271%27%3D%271%27+--"
    }
  ]
}
```

### CSV

```
vulnerable,param,payload,evidence,status_code,response_length,url
True,id,' OR '1'='1' --,SQL error pattern matched,200,6641,http://target.lab/?id=...
```

### TXT

```
VulnHunter Scan Report
Target  : http://target.lab/?id=1
Module  : sqli
Time    : 2026-03-22T16:53:23Z
Results : 3 vulnerabilities from 31 tests

[1] param=id  payload=' OR '1'='1' --
    evidence : SQL error pattern matched: 'you have an error in your sql syntax'
    url      : http://target.lab/?id=%27+OR+%271%27%3D%271%27+--
```

---

## Project Structure

```
vulnhunter_v3/
├── main.py                     # CLI entry point and argument parser
├── requirements.txt            # Runtime dependencies
├── pyproject.toml              # Package config and pytest settings
├── CHANGELOG.md
├── CONTRIBUTING.md
│
├── core/
│   ├── banner.py               # Terminal banner, colors, and output helpers
│   ├── config.py               # Config dataclass — CLI args and YAML loading
│   ├── engine.py               # Scan pipeline: probe → WAF → fingerprint → scan → report
│   ├── module_loader.py        # Dynamic plugin loader and module registry
│   └── waf.py                  # WAF detection heuristics
│
├── modules/
│   ├── base.py                 # Abstract base class all modules inherit from
│   ├── sqli.py                 # SQL Injection
│   ├── xss.py                  # Cross-Site Scripting
│   ├── auth.py                 # Authentication Brute-Force
│   ├── lfi.py                  # Local File Inclusion
│   ├── ssrf.py                 # Server-Side Request Forgery
│   ├── redirect.py             # Open Redirect
│   ├── idor.py                 # Insecure Direct Object Reference
│   └── cmdi.py                 # OS Command Injection
│
├── utils/
│   ├── request_handler.py      # Thread-safe HTTP client with retry and proxy support
│   ├── fingerprint.py          # Server and framework fingerprinting
│   ├── helpers.py              # URL parameter extraction and payload injection
│   └── logger.py               # Colored structured logging
│
├── payloads/
│   ├── sqli.json               # SQL injection payload list
│   ├── xss.json                # XSS payload list
│   ├── lfi.json                # LFI path traversal list
│   └── credentials.txt         # Default credential pairs for auth module
│
├── profiles/
│   └── example_ctf.yaml        # Example YAML scan profile
│
└── tests/
    ├── conftest.py
    ├── test_config.py
    ├── test_helpers.py
    ├── test_module_loader.py
    ├── test_module_sqli.py
    ├── test_modules.py
    └── test_waf_fingerprint.py
```

---

## Running Tests

```bash
# Run the full test suite
pytest

# With line-by-line coverage report
pytest --cov=. --cov-report=term-missing

# Run a specific test file
pytest tests/test_modules.py -v

# Filter tests by keyword
pytest -k "sqli or xss" -v

# Stop on first failure
pytest -x
```

---

## Writing a Custom Module

VulnHunter's plugin system makes adding new vulnerability classes straightforward.

**Step 1 — Create `modules/mymodule.py`:**

```python
import time
from modules.base import BaseModule
from utils.helpers import extract_params, inject_param
from typing import List, Dict, Any


class MyModule(BaseModule):

    def load_payloads(self) -> List[str]:
        if self.config.wordlist:
            return self._load_external_wordlist(self.config.wordlist)
        return ["payload1", "payload2"]

    def execute(self) -> List[Dict[str, Any]]:
        payloads = self.load_payloads()
        params = extract_params(self.config.url, self.config.param)
        results = []
        for param in params:
            for payload in payloads:
                if self.config.delay:
                    time.sleep(self.config.delay)
                url = inject_param(self.config.url, param, payload)
                resp = self.http.get(url)
                if resp:
                    results.append(self.analyze_response(resp, payload, param))
        return results

    def analyze_response(self, response, payload: str, param: str, **kwargs) -> Dict[str, Any]:
        return {
            "payload": payload,
            "param": param,
            "vulnerable": "MARKER" in response.text,
            "evidence": "Marker string found in response body",
            "status_code": response.status_code,
            "response_length": len(response.content),
            "url": response.url,
        }
```

**Step 2 — Register it in `core/module_loader.py`:**

```python
MODULE_REGISTRY = {
    # ... existing modules ...
    "mymodule": ("modules.mymodule", "MyModule"),
}
```

**Step 3 — Use it:**

```bash
python main.py --url "http://target.lab/?id=1" --module mymodule
```

---

## Authorized Practice Targets

The following platforms provide legal, isolated environments for security testing:

| Platform | Type | URL |
|---|---|---|
| **DVWA** | Local Docker / VM | `http://localhost/dvwa` |
| **Vulnweb Demo** | Live test site | http://testphp.vulnweb.com |
| **HackTheBox** | CTF / Pro Labs | https://www.hackthebox.com |
| **TryHackMe** | Guided rooms | https://tryhackme.com |
| **PentesterLab** | Web security exercises | https://pentesterlab.com |
| **PortSwigger Web Academy** | Burp Suite labs | https://portswigger.net/web-security |
| **VulnHub** | Downloadable VMs | https://www.vulnhub.com |

> Always verify you are scanning machines assigned to your account and operating within each platform's terms of service.

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

- **Bug reports** — Open a GitHub Issue with reproduction steps, your OS, Python version, and the exact command run
- **New modules** — Follow the custom module guide above and include unit tests in `tests/`
- **Payload improvements** — Submit additions to the JSON payload files with a comment describing the bypass technique

---

## Legal Disclaimer

VulnHunter is provided for **educational and authorized security testing purposes only**. You are solely responsible for ensuring you have explicit written permission before scanning any system. Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), and equivalent legislation in your jurisdiction.

**The authors and contributors accept no responsibility or liability for any misuse or damage caused by this tool.**

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for full terms.

---

<div align="center">

Built for learning · Use responsibly · Happy hunting 🎯

**[Report a Bug](https://github.com/vulnhunter/vulnhunter/issues) · [Request a Feature](https://github.com/vulnhunter/vulnhunter/issues) · [View Changelog](CHANGELOG.md)**

</div>
