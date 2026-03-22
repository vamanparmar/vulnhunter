# Changelog

All notable changes to VulnHunter are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [3.0.0] — 2024-11-01 · Codename: RedSight

### Added
- **IDOR module** — enumerates numeric/UUID IDs, detects PII leakage, 403→200 flips, and response length deltas
- **CMDi module** — OS command injection with output-based, time-based blind, and error-based detection. Covers Unix + Windows
- **Full pytest test suite** — 50+ unit tests across `test_config.py`, `test_helpers.py`, `test_module_sqli.py`, `test_modules.py`, `test_waf_fingerprint.py`, `test_module_loader.py`
- **`pyproject.toml`** — proper Python packaging; `pip install -e .[dev]` installs all dev dependencies
- **`CHANGELOG.md`** and **`CONTRIBUTING.md`** for open-source readiness
- `--output-format csv` now produces per-result rows with all key fields

### Changed
- Module registry expanded from 6 to 8 modules
- `main.py` `--module` choices updated to include `idor` and `cmdi`
- CMDi uses two-phase scan: parallel output-based, then sequential time-based

---

## [2.0.0] — 2024-10-15 · Codename: RedSight

### Added
- **SSRF module** — loopback, cloud metadata (AWS/GCP/Azure), RFC-1918, protocol wrappers, encoded bypasses
- **Open Redirect module** — Location header, meta-refresh, and JavaScript redirect detection
- **YAML profile system** — `--profile profiles/ctf.yaml`; CLI args override profile values
- **`--silent` mode** — suppress all output except confirmed findings
- **`--output-format`** — choose between `json`, `csv`, and `txt` report formats
- **`--rate-limit`**, **`--encoding`**, **`--user-agent`**, **`--no-redirects`** CLI flags
- `Config.from_yaml()` class method with override merging
- `Config.to_dict()` serialisation helper
- Separate `findings` vs `all_results` sections in JSON output

### Changed
- Banner upgraded to block-letter Unicode art with metadata info table
- All scan output uses `[✔]` / `[✗]` / `[!]` / `[*]` prefixed lines
- Engine broken into named pipeline methods (`_probe_target`, `_detect_waf`, etc.)
- Final summary rendered as a structured boxed table with confirmed findings listed

---

## [1.0.0] — 2024-10-01

### Added
- Initial release with SQLi, XSS, Auth brute-force, and LFI modules
- Plugin-based module architecture via `MODULE_REGISTRY`
- WAF detection heuristics (Cloudflare, ModSecurity, Sucuri, Akamai, F5, Imperva)
- Target fingerprinting (server, framework, cookie flags, security headers)
- Multi-threaded request engine with retry, proxy, session persistence
- `--dry-run`, `--verbose`, `--proxy`, `--headers`, `--cookies`, `--delay` flags
- JSON output report with meta, summary, and results sections
- Payload files: `sqli.json`, `xss.json`, `lfi.json`, `credentials.txt`
