"""
utils/fingerprint.py
--------------------
Target fingerprinting from HTTP response headers.

Extracts server, framework, and technology stack information
to help contextualize scan results.
"""

from typing import Dict, Optional
import re


# Common framework/CMS detection via response headers or body hints
FRAMEWORK_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "wp-json", "x-powered-by: php"],
    "Drupal": ["drupal.js", "x-generator: drupal", "sites/default/files"],
    "Joomla": ["joomla!", "/components/com_"],
    "Laravel": ["laravel_session", "x-powered-by: php"],
    "Django": ["csrfmiddlewaretoken", "x-frame-options: sameorigin"],
    "Ruby on Rails": ["x-powered-by: phusion passenger", "_rails_session"],
    "ASP.NET": ["x-powered-by: asp.net", "x-aspnet-version", "__viewstate"],
    "Express.js": ["x-powered-by: express"],
    "Spring": ["x-application-context", "jsessionid"],
}


def fingerprint_target(response) -> Dict[str, Optional[str]]:
    """
    Extract server and framework info from an HTTP response.

    Args:
        response: A requests.Response object.

    Returns:
        Dictionary with fingerprint keys and detected values.
    """
    headers = {k.lower(): v for k, v in response.headers.items()}
    body = response.text.lower()

    fingerprint = {
        "Server": headers.get("server"),
        "X-Powered-By": headers.get("x-powered-by"),
        "Content-Type": headers.get("content-type"),
        "Framework": _detect_framework(headers, body),
        "Cookie-Flags": _analyze_cookies(response),
        "Security-Headers": _check_security_headers(headers),
    }

    return {k: v for k, v in fingerprint.items() if v}


def _detect_framework(headers: Dict[str, str], body: str) -> Optional[str]:
    """Attempt to identify the framework from headers and body."""
    # Include both values-only AND key: value pairs so signatures like
    # 'x-powered-by: express' match against the full header representation
    header_values = " ".join(headers.values())
    header_pairs  = " ".join(f"{k}: {v}" for k, v in headers.items())
    combined = header_values + " " + header_pairs + " " + body

    for framework, signatures in FRAMEWORK_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in combined.lower():
                return framework

    return None


def _analyze_cookies(response) -> Optional[str]:
    """Check Set-Cookie flags (HttpOnly, Secure, SameSite)."""
    set_cookie = response.headers.get("Set-Cookie", "")
    if not set_cookie:
        return None

    flags = []
    if "httponly" not in set_cookie.lower():
        flags.append("Missing HttpOnly")
    if "secure" not in set_cookie.lower():
        flags.append("Missing Secure")
    if "samesite" not in set_cookie.lower():
        flags.append("Missing SameSite")

    return ", ".join(flags) if flags else "HttpOnly+Secure+SameSite present"


def _check_security_headers(headers: Dict[str, str]) -> Optional[str]:
    """Report missing security headers."""
    important_headers = [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "strict-transport-security",
    ]
    missing = [h for h in important_headers if h not in headers]
    if missing:
        return f"Missing: {', '.join(missing)}"
    return "All key security headers present"
