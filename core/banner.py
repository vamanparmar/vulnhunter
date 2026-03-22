"""
core/banner.py
--------------
Professional ASCII banner with rich terminal formatting,
version metadata, and system environment display.
"""

import sys
import platform
import datetime
from typing import Optional

VERSION = "3.0.0"
AUTHOR = "VulnHunter Project"
GITHUB = "github.com/vulnhunter/vulnhunter"
LICENSE = "MIT"
CODENAME = "RedSight"


class Color:
    """ANSI escape codes for terminal coloring."""
    RESET       = "\033[0m"
    BOLD        = "\033[1m"
    DIM         = "\033[2m"

    RED         = "\033[31m"
    GREEN       = "\033[32m"
    YELLOW      = "\033[33m"
    CYAN        = "\033[36m"
    WHITE       = "\033[37m"

    BRIGHT_RED      = "\033[91m"
    BRIGHT_GREEN    = "\033[92m"
    BRIGHT_YELLOW   = "\033[93m"
    BRIGHT_BLUE     = "\033[94m"
    BRIGHT_CYAN     = "\033[96m"
    BRIGHT_WHITE    = "\033[97m"

    BG_RED      = "\033[41m"

    @staticmethod
    def strip(text: str) -> str:
        """Remove all ANSI codes from a string."""
        import re
        return re.sub(r'\033\[[0-9;]*m', '', text)


BANNER_ART = r"""
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""


def _c(text: str, *codes: str, no_color: bool = False) -> str:
    """Apply ANSI color codes if color is enabled."""
    if no_color:
        return text
    return "".join(codes) + text + Color.RESET


def print_banner(no_color: bool = False) -> None:
    """Print the professional VulnHunter banner with metadata table."""
    now    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    os_info= f"{platform.system()} {platform.release()}"

    print(_c(BANNER_ART, Color.BRIGHT_RED, Color.BOLD, no_color=no_color))
    subtitle = f"   Modular Web Exploitation Framework  ·  Codename: {CODENAME}  ·  v{VERSION}"
    print(_c(subtitle, Color.BRIGHT_CYAN, Color.BOLD, no_color=no_color))
    print()

    W = 54
    rows = [
        ("Version",   f"v{VERSION}  [{CODENAME}]"),
        ("Author",    AUTHOR),
        ("GitHub",    GITHUB),
        ("License",   LICENSE),
        ("Python",    py_ver),
        ("Platform",  os_info),
        ("Started",   now),
    ]

    def hline(l, r, mid="═"):
        return _c(f"  {l}" + mid * W + f"{r}", Color.DIM, Color.CYAN, no_color=no_color)

    print(hline("╔", "╗"))
    for i, (key, val) in enumerate(rows):
        k = _c(f"  {key:<13}", Color.BRIGHT_YELLOW, no_color=no_color)
        v = _c(val, Color.BRIGHT_WHITE, no_color=no_color)
        pipe = _c("║  ", Color.DIM, Color.CYAN, no_color=no_color)
        # Visible chars: "║  " (3) + "  " (2) + key padded to 13 + "  " (2) + val = 20 + len(val)
        pad = " " * max(0, W - 20 - len(val))
        end = _c(f"{pad}║", Color.DIM, Color.CYAN, no_color=no_color)
        print(f"{pipe}{k}  {v}{end}")

    print(hline("╠", "╣"))
    warn = "  ⚠  FOR AUTHORIZED TESTING & CTF USE ONLY"
    # ⚠ (⚠) is double-width in most terminals — count it as 2 columns
    warn_vis_width = len(warn) + 1
    warn_pad = " " * max(0, W - warn_vis_width)
    print(_c(f"  ║{warn}{warn_pad}║", Color.BRIGHT_RED, Color.BOLD, no_color=no_color))
    print(hline("╚", "╝"))
    print()


def print_section(title: str, no_color: bool = False) -> None:
    """Print a styled section header."""
    line = "─" * (len(title) + 4)
    print()
    print(_c(f"  ┌{line}┐", Color.DIM, Color.CYAN, no_color=no_color))
    print(_c(f"  │  {title}  │", Color.BRIGHT_CYAN, Color.BOLD, no_color=no_color))
    print(_c(f"  └{line}┘", Color.DIM, Color.CYAN, no_color=no_color))


def print_finding(param: str, payload: str, evidence: str, url: str = "", no_color: bool = False) -> None:
    """Print a highlighted vulnerability finding."""
    tag     = _c(" VULN ", Color.BG_RED, Color.BRIGHT_WHITE, Color.BOLD, no_color=no_color)
    sep     = _c(" ▶ ", Color.BRIGHT_RED, no_color=no_color)
    p_val   = _c(param,   Color.BRIGHT_YELLOW, Color.BOLD, no_color=no_color)
    pay_val = _c((payload[:55] + "…") if len(payload) > 55 else payload, Color.BRIGHT_WHITE, no_color=no_color)
    ev_val  = _c(evidence, Color.BRIGHT_GREEN, no_color=no_color)
    print(f"  {tag}{sep}param={p_val}  payload={pay_val}")
    print(_c(f"          evidence: {evidence}", Color.DIM, no_color=no_color))
    if url:
        print(_c(f"          url:      {url[:80]}", Color.DIM, no_color=no_color))


def print_info(label: str, value: str, no_color: bool = False) -> None:
    lbl = _c(f"  [{label}]", Color.BRIGHT_CYAN, no_color=no_color)
    val = _c(value, Color.BRIGHT_WHITE, no_color=no_color)
    print(f"{lbl} {val}")


def print_warn(message: str, no_color: bool = False) -> None:
    tag = _c("  [!]", Color.BRIGHT_YELLOW, Color.BOLD, no_color=no_color)
    msg = _c(message, Color.YELLOW, no_color=no_color)
    print(f"{tag} {msg}")


def print_error(message: str, no_color: bool = False) -> None:
    tag = _c("  [✗]", Color.BRIGHT_RED, Color.BOLD, no_color=no_color)
    msg = _c(message, Color.RED, no_color=no_color)
    print(f"{tag} {msg}")


def print_success(message: str, no_color: bool = False) -> None:
    tag = _c("  [✔]", Color.BRIGHT_GREEN, Color.BOLD, no_color=no_color)
    msg = _c(message, Color.BRIGHT_GREEN, no_color=no_color)
    print(f"{tag} {msg}")


def print_step(message: str, no_color: bool = False) -> None:
    tag = _c("  [*]", Color.BRIGHT_BLUE, no_color=no_color)
    msg = _c(message, Color.WHITE, no_color=no_color)
    print(f"{tag} {msg}")


def print_summary_table(results: list, elapsed: float, no_color: bool = False) -> None:
    """Print a structured summary table at the end of a scan."""
    total    = len(results)
    hits     = [r for r in results if r.get("vulnerable")]
    hit_ct   = len(hits)
    clean_ct = total - hit_ct

    W = 46
    def hline(l, r, mid="═"):
        return _c(f"  {l}" + mid * W + f"{r}", Color.DIM, Color.CYAN, no_color=no_color)

    def row(label: str, value: str, vcolor: str = Color.BRIGHT_WHITE) -> None:
        lbl = _c(f"  ║  {label:<22}", Color.DIM, Color.WHITE, no_color=no_color)
        val = _c(f"{value}", vcolor, no_color=no_color)
        # Visible: "  ║  " (5) + label padded to 22 + value = 27 + len(value)
        pad = " " * max(0, W - 27 - len(value))
        end = _c(f"{pad}║", Color.DIM, Color.CYAN, no_color=no_color)
        print(f"{lbl}{val}{end}")

    print()
    title = "SCAN SUMMARY"
    title_pad_l = " " * ((W - len(title)) // 2)
    title_pad_r = " " * (W - len(title) - len(title_pad_l))
    print(hline("╔", "╗"))
    print(_c(f"  ║{title_pad_l}{title}{title_pad_r}║", Color.BRIGHT_CYAN, Color.BOLD, no_color=no_color))
    print(hline("╠", "╣"))
    row("Payloads Tested",  str(total))
    vuln_color = Color.BRIGHT_RED if hit_ct > 0 else Color.BRIGHT_GREEN
    row("Vulnerabilities",  str(hit_ct) + ("  ← FOUND" if hit_ct else "  ← Clean"), vuln_color)
    row("Clean Responses",  str(clean_ct), Color.BRIGHT_GREEN)
    row("Elapsed Time",     f"{elapsed:.2f}s")
    print(hline("╚", "╝"))

    if hits:
        print()
        print(_c("  ┌─ Confirmed Findings " + "─" * 25 + "┐", Color.BRIGHT_RED, no_color=no_color))
        for i, hit in enumerate(hits, 1):
            num  = _c(f"  │  #{i}", Color.BRIGHT_RED, no_color=no_color)
            par  = _c(f"param={hit.get('param','?')}", Color.BRIGHT_YELLOW, no_color=no_color)
            pay  = _c(str(hit.get('payload',''))[:40], Color.WHITE, no_color=no_color)
            print(f"{num}  {par}  payload={pay}")
            print(_c(f"  │       evidence : {hit.get('evidence','N/A')}", Color.DIM, no_color=no_color))
            print(_c(f"  │       url      : {str(hit.get('url','N/A'))[:70]}", Color.DIM, no_color=no_color))
            if i < len(hits):
                print(_c("  │  " + "·" * 44, Color.DIM, no_color=no_color))
        print(_c("  └" + "─" * 48 + "┘", Color.BRIGHT_RED, no_color=no_color))
    print()
