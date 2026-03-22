"""
tests/test_waf_fingerprint.py
------------------------------
Unit tests for WAF detection (core/waf.py) and
target fingerprinting (utils/fingerprint.py).
"""

import pytest
from unittest.mock import MagicMock
from core.waf import WAFDetector
from utils.fingerprint import fingerprint_target
from tests.conftest import make_config, make_response


@pytest.fixture
def http_mock():
    return MagicMock()


# ── WAF Detection ────────────────────────────────────────────────────────────

class TestWAFDetector:

    def test_cloudflare_detected_via_header(self, http_mock):
        resp = make_response(
            status_code=403,
            headers={"cf-ray": "abc123", "server": "cloudflare"},
        )
        http_mock.get.return_value = resp
        detector = WAFDetector(http_mock, "http://target.lab/")
        result = detector.detect()
        assert result == "Cloudflare"

    def test_modsecurity_detected_via_body(self, http_mock):
        resp = make_response(
            status_code=406,
            text="406 Not Acceptable — ModSecurity blocked this request",
            headers={"server": "Apache"},
        )
        http_mock.get.return_value = resp
        detector = WAFDetector(http_mock, "http://target.lab/")
        result = detector.detect()
        assert result == "ModSecurity"

    def test_sucuri_detected_via_body(self, http_mock):
        resp = make_response(
            status_code=403,
            text="Access Denied - Sucuri Website Firewall",
            headers={},
        )
        http_mock.get.return_value = resp
        detector = WAFDetector(http_mock, "http://target.lab/")
        result = detector.detect()
        assert result == "Sucuri"

    def test_no_waf_returns_none(self, http_mock):
        resp = make_response(
            status_code=200,
            text="<html><body>Normal page</body></html>",
            headers={"server": "Apache/2.4.41"},
        )
        http_mock.get.return_value = resp
        detector = WAFDetector(http_mock, "http://target.lab/")
        result = detector.detect()
        assert result is None

    def test_connection_drop_returns_none(self, http_mock):
        # A connection drop is inconclusive — should NOT falsely assert a WAF is present
        http_mock.get.return_value = None
        detector = WAFDetector(http_mock, "http://target.lab/")
        result = detector.detect()
        assert result is None  # fixed: was 'Unknown WAF (connection dropped)', now correctly None


# ── Fingerprinting ───────────────────────────────────────────────────────────

class TestFingerprint:

    def test_server_header_extracted(self):
        resp = make_response(headers={"server": "nginx/1.24.0"})
        info = fingerprint_target(resp)
        assert info.get("Server") == "nginx/1.24.0"

    def test_x_powered_by_extracted(self):
        resp = make_response(headers={"x-powered-by": "PHP/8.2.0"})
        info = fingerprint_target(resp)
        assert info.get("X-Powered-By") == "PHP/8.2.0"

    def test_wordpress_detected_via_body(self):
        resp = make_response(
            text="<link rel='stylesheet' href='/wp-content/themes/style.css'>",
            headers={},
        )
        info = fingerprint_target(resp)
        assert info.get("Framework") == "WordPress"

    def test_express_detected_via_header(self):
        resp = make_response(headers={"x-powered-by": "Express"})
        info = fingerprint_target(resp)
        assert info.get("Framework") == "Express.js"

    def test_missing_security_headers_reported(self):
        resp = make_response(headers={"server": "nginx"})
        info = fingerprint_target(resp)
        security = info.get("Security-Headers", "")
        assert "Missing" in security

    def test_returns_dict(self):
        resp = make_response()
        info = fingerprint_target(resp)
        assert isinstance(info, dict)

    def test_empty_values_filtered(self):
        resp = make_response(headers={})
        info = fingerprint_target(resp)
        # No None values should appear in output
        for v in info.values():
            assert v is not None
