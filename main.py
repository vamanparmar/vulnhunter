#!/usr/bin/env python3
"""
VulnHunter v3.0 — Modular Web Exploitation Framework
=====================================================
For educational purposes and authorized penetration testing ONLY.
Do NOT use against targets you do not have explicit written permission to test.
"""

import sys
import argparse
import json
from pathlib import Path

from core.config import Config
from core.engine import Engine
from core.banner import print_banner, print_error
from core.module_loader import list_modules
from utils.logger import setup_logger, get_logger


def parse_arguments() -> argparse.Namespace:
    """Parse and validate CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="vulnhunter",
        description="VulnHunter v3.0 — Modular Web Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # SQL injection scan with output
  python main.py --url "http://testphp.vulnweb.com/listproducts.php?cat=1" --module sqli --output report.json

  # XSS with rate limiting through Burp Suite proxy
  python main.py --url "http://target.lab/search?q=1" --module xss --proxy http://127.0.0.1:8080 --delay 0.5

  # Auth brute force with custom wordlist
  python main.py --url "http://target.lab/login" --module auth --wordlist payloads/credentials.txt --threads 3

  # LFI with specific parameter targeting
  python main.py --url "http://target.lab/index.php?page=home" --module lfi --param page

  # SSRF scan
  python main.py --url "http://target.lab/fetch?url=http://example.com" --module ssrf --param url

  # Dry run to validate config without sending payloads
  python main.py --url "http://target.lab/?id=1" --module sqli --dry-run --verbose

  # Load from YAML profile
  python main.py --profile profiles/ctf_lab.yaml

  # Silent mode (only print findings)
  python main.py --url "http://target.lab/?id=1" --module sqli --silent --output findings.csv --output-format csv

⚠  FOR AUTHORIZED TESTING AND CTF CHALLENGES ONLY
        """,
    )

    # Required (can be omitted if --profile is used)
    target = parser.add_argument_group("Target")
    target.add_argument("--url",     help="Target URL (e.g. http://target.lab/search?q=1)")
    target.add_argument("--module",  choices=list_modules(), help="Exploit module to use")
    target.add_argument("--profile", help="Path to YAML profile file (overrides --url/--module defaults)")

    # Request config
    req = parser.add_argument_group("Request Options")
    req.add_argument("--threads",   type=int,   default=5,    help="Thread count (default: 5)")
    req.add_argument("--timeout",   type=int,   default=10,   help="Request timeout seconds (default: 10)")
    req.add_argument("--proxy",                               help="Proxy URL (e.g. http://127.0.0.1:8080)")
    req.add_argument("--headers",                             help='JSON headers: \'{"X-Token": "abc"}\'')
    req.add_argument("--cookies",                             help='JSON cookies: \'{"session": "xyz"}\'')
    req.add_argument("--delay",     type=float, default=0.0,  help="Delay between requests in seconds (default: 0)")
    req.add_argument("--retries",   type=int,   default=3,    help="Max retries per request (default: 3)")
    req.add_argument("--user-agent",                          help="Custom User-Agent string")
    req.add_argument("--no-redirects", action="store_true",   help="Disable following redirects")
    req.add_argument("--rate-limit",type=int,   default=0,    help="Max requests per second (0=unlimited)")

    # Payload options
    pay = parser.add_argument_group("Payload Options")
    pay.add_argument("--wordlist",                            help="Path to custom payload wordlist")
    pay.add_argument("--param",                               help="Parameter to inject (overrides auto-detect)")
    pay.add_argument("--encoding",  choices=["none","url","double-url","html"], default="none",
                     help="Payload encoding (default: none)")

    # Output options
    out = parser.add_argument_group("Output Options")
    out.add_argument("--output",                              help="Save report to file")
    out.add_argument("--output-format", choices=["json","csv","txt"], default="json",
                     help="Output format (default: json)")
    out.add_argument("--verbose",   action="store_true",      help="Enable debug logging")
    out.add_argument("--silent",    action="store_true",      help="Suppress all output except findings")
    out.add_argument("--dry-run",   action="store_true",      help="Validate config without sending payloads")
    out.add_argument("--no-color",  action="store_true",      help="Disable ANSI color output")

    return parser.parse_args()


def build_config(args: argparse.Namespace) -> Config:
    """Build a Config object from parsed CLI arguments or YAML profile."""
    logger = get_logger()

    # Parse optional JSON args
    headers: dict = {}
    cookies: dict = {}

    if args.headers:
        try:
            headers = json.loads(args.headers)
        except json.JSONDecodeError:
            print_error("Invalid JSON for --headers.", no_color=args.no_color)
            sys.exit(1)

    if args.cookies:
        try:
            cookies = json.loads(args.cookies)
        except json.JSONDecodeError:
            print_error("Invalid JSON for --cookies.", no_color=args.no_color)
            sys.exit(1)

    # If a profile is given, load it and merge CLI overrides
    if args.profile:
        cli_overrides = {
            "url":              args.url,
            "module":           args.module,
            "threads":          args.threads if args.threads != 5 else None,
            "timeout":          args.timeout if args.timeout != 10 else None,
            "proxy":            args.proxy,
            "headers":          headers or None,
            "cookies":          cookies or None,
            "delay":            args.delay if args.delay != 0.0 else None,
            "retries":          args.retries if args.retries != 3 else None,
            "wordlist":         args.wordlist,
            "param":            args.param,
            "output":           args.output,
            "output_format":    args.output_format,
            "verbose":          args.verbose or None,
            "dry_run":          args.dry_run or None,
            "no_color":         args.no_color or None,
            "silent":           args.silent or None,
            "user_agent":       args.user_agent,
            "rate_limit":       args.rate_limit if args.rate_limit != 0 else None,
        }
        try:
            return Config.from_yaml(args.profile, overrides={k: v for k, v in cli_overrides.items() if v is not None})
        except (FileNotFoundError, ValueError, ImportError) as e:
            print_error(str(e), no_color=args.no_color)
            sys.exit(1)

    # Require --url and --module when no profile
    if not args.url or not args.module:
        print_error("--url and --module are required (or use --profile).", no_color=args.no_color)
        sys.exit(1)

    return Config(
        url=args.url,
        module=args.module,
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        headers=headers,
        cookies=cookies,
        delay=args.delay,
        retries=args.retries,
        rate_limit=args.rate_limit,
        wordlist=args.wordlist,
        param=args.param,
        payload_encoding=args.encoding,
        output=args.output,
        output_format=args.output_format,
        verbose=args.verbose,
        dry_run=args.dry_run,
        no_color=args.no_color,
        silent=args.silent,
        follow_redirects=not args.no_redirects,
        user_agent=args.user_agent,
    )


def main() -> None:
    """Main entry point."""
    args = parse_arguments()

    setup_logger(verbose=args.verbose, no_color=args.no_color)

    if not args.silent:
        print_banner(no_color=args.no_color)

    config = build_config(args)

    if not config.url.startswith(("http://", "https://")):
        print_error("URL must begin with http:// or https://", no_color=config.no_color)
        sys.exit(1)

    try:
        engine = Engine(config)
        engine.run()
    except KeyboardInterrupt:
        print_error("\nScan interrupted by user.", no_color=config.no_color)
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}", no_color=config.no_color)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
