"""
utils/helpers.py
----------------
Shared helper utilities for URL manipulation, parameter extraction,
and payload injection.
"""

from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def extract_params(url: str, override_param: Optional[str] = None) -> List[str]:
    """
    Extract injectable parameter names from a URL query string.

    If override_param is provided, return only that parameter.

    Args:
        url: The target URL.
        override_param: Optional specific parameter to target.

    Returns:
        List of parameter names.
    """
    if override_param:
        return [override_param]

    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
    return params


def inject_param(url: str, param: str, payload: str) -> str:
    """
    Replace the value of a specific URL parameter with a payload.

    If the parameter doesn't exist, append it.

    Args:
        url: The base URL.
        param: The parameter name to inject into.
        payload: The injection payload value.

    Returns:
        Modified URL with the injected payload.
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)

    # Inject payload (replace existing or add new)
    query_params[param] = [payload]

    # Rebuild URL — use doseq to handle list values correctly
    new_query = urlencode(query_params, doseq=True)
    new_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment,
    ))
    return new_url


def truncate(text: str, max_length: int = 80) -> str:
    """Truncate a string for display purposes."""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def sanitize_filename(name: str) -> str:
    """Convert a string into a safe filename."""
    import re
    return re.sub(r"[^a-zA-Z0-9_\-\.]", "_", name)
