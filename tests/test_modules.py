"""
tests/test_modules.py
---------------------
Unit tests for XSS, LFI, IDOR, and CMDi modules.
Focused on analyze_response() and load_payloads() logic.
"""

import pytest
from unittest.mock import MagicMock
from modules.xss import XSSModule
from modules.lfi import LFIModule
from modules.idor import IDORModule
from modules.cmdi import CMDiModule
from tests.conftest import make_config, make_response


# ── XSS ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def xss(mock_http):
    return XSSModule(make_config(module="xss"), mock_http)


class TestXSSModule:

    def test_default_payloads_not_empty(self, xss):
        assert len(xss.load_payloads()) > 0

    def test_verbatim_reflection_detected(self, xss):
        payload = "<script>alert(1)</script>"
        resp = make_response(text=f"<html>{payload}</html>")
        result = xss.analyze_response(resp, payload, "q")
        assert result["vulnerable"] is True
        assert "verbatim" in result["evidence"].lower()

    def test_onerror_reflection_detected(self, xss):
        resp = make_response(text='<img src=x onerror=alert(1)>')
        result = xss.analyze_response(resp, "<img src=x onerror=alert(1)>", "q")
        assert result["vulnerable"] is True

    def test_alert_token_detected(self, xss):
        resp = make_response(text="<div>alert(1)</div>")
        result = xss.analyze_response(resp, "alert(1)", "q")
        assert result["vulnerable"] is True

    def test_html_encoded_not_flagged_as_vuln(self, xss):
        """HTML-encoded reflection is detected but NOT marked exploitable."""
        payload = "<script>alert(1)</script>"
        encoded = "&lt;script&gt;alert(1)&lt;/script&gt;"
        resp = make_response(text=f"<html>{encoded}</html>")
        result = xss.analyze_response(resp, payload, "q")
        assert result["vulnerable"] is False
        assert "encoded" in result["evidence"].lower()

    def test_clean_response_not_flagged(self, xss):
        resp = make_response(text="<html><body>Search results</body></html>")
        result = xss.analyze_response(resp, "<script>alert(1)</script>", "q")
        assert result["vulnerable"] is False

    def test_result_has_required_keys(self, xss):
        resp = make_response(text="ok")
        result = xss.analyze_response(resp, "test", "q")
        for key in ("payload", "param", "vulnerable", "evidence"):
            assert key in result


# ── LFI ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def lfi(mock_http):
    return LFIModule(make_config(module="lfi"), mock_http)


class TestLFIModule:

    def test_default_payloads_not_empty(self, lfi):
        assert len(lfi.load_payloads()) > 0

    def test_etc_passwd_detected(self, lfi):
        resp = make_response(text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
        result = lfi.analyze_response(resp, "../../etc/passwd", "file")
        assert result["vulnerable"] is True
        assert "root:x:0:0:" in result["evidence"]

    def test_win_ini_detected(self, lfi):
        resp = make_response(text="[fonts]\n[extensions]\n")
        result = lfi.analyze_response(resp, "../../windows/win.ini", "file")
        assert result["vulnerable"] is True

    def test_proc_version_detected(self, lfi):
        resp = make_response(text="Linux version 5.15.0-generic (buildd@lcy02)")
        result = lfi.analyze_response(resp, "/proc/version", "file")
        assert result["vulnerable"] is True

    def test_clean_response_not_flagged(self, lfi):
        resp = make_response(text="<html>Page not found</html>")
        result = lfi.analyze_response(resp, "../../etc/passwd", "file")
        assert result["vulnerable"] is False


# ── IDOR ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def idor(mock_http):
    return IDORModule(make_config(module="idor"), mock_http)


class TestIDORModule:

    def test_default_payloads_include_numeric_ids(self, idor):
        payloads = idor.load_payloads()
        assert "1" in payloads
        assert "2" in payloads

    def test_default_payloads_include_boundary_values(self, idor):
        payloads = idor.load_payloads()
        assert "0" in payloads
        assert "-1" in payloads

    def test_email_pattern_detected(self, idor):
        resp = make_response(text='{"email":"victim@example.com","name":"Alice"}')
        baseline = {"status": 200, "length": 30, "body": "{}"}
        result = idor.analyze_response(resp, "2", "id", baseline)
        assert result["vulnerable"] is True
        assert "email" in result["evidence"].lower() or "sensitive" in result["evidence"].lower()

    def test_password_field_detected(self, idor):
        resp = make_response(text='{"username":"admin","password":"secret123"}')
        baseline = {"status": 200, "length": 10, "body": "{}"}
        result = idor.analyze_response(resp, "1", "id", baseline)
        assert result["vulnerable"] is True

    def test_403_to_200_flip_detected(self, idor):
        resp = make_response(status_code=200, text='{"data":"something"}')
        baseline = {"status": 403, "length": 50, "body": "Forbidden"}
        result = idor.analyze_response(resp, "2", "id", baseline)
        assert result["vulnerable"] is True
        assert "403" in result["evidence"]

    def test_clean_response_not_flagged(self, idor):
        body = '{"id":1,"name":"test"}'
        resp = make_response(text=body)
        baseline = {"status": 200, "length": len(body), "body": body}
        result = idor.analyze_response(resp, "1", "id", baseline)
        assert result["vulnerable"] is False

    def test_api_token_detected(self, idor):
        resp = make_response(text='{"api_key":"abcdef1234567890abcdef1234"}')
        baseline = {"status": 200, "length": 10, "body": "{}"}
        result = idor.analyze_response(resp, "5", "id", baseline)
        assert result["vulnerable"] is True


# ── CMDi ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def cmdi(mock_http):
    return CMDiModule(make_config(module="cmdi"), mock_http)


class TestCMDiModule:

    def test_default_payloads_not_empty(self, cmdi):
        assert len(cmdi.load_payloads()) > 0

    def test_uid_output_detected(self, cmdi):
        resp = make_response(text="uid=0(root) gid=0(root) groups=0(root)")
        result = cmdi.analyze_response(resp, ";id", "cmd", expected_sig="uid=")
        assert result["vulnerable"] is True
        assert "uid=" in result["evidence"]

    def test_passwd_output_detected(self, cmdi):
        resp = make_response(text="root:x:0:0:root:/root:/bin/bash")
        result = cmdi.analyze_response(resp, ";cat /etc/passwd", "input", expected_sig="root:x:0:")
        assert result["vulnerable"] is True

    def test_shell_error_detected(self, cmdi):
        resp = make_response(text="sh: 1: invalid_cmd_xyz_123: not found")
        result = cmdi.analyze_response(resp, ";invalid_cmd_xyz_123", "q", expected_sig="uid=")
        assert result["vulnerable"] is True
        assert "shell error" in result["evidence"].lower()

    def test_windows_whoami_detected(self, cmdi):
        resp = make_response(text="nt authority\\system")
        result = cmdi.analyze_response(resp, "& whoami", "q", expected_sig="nt authority")
        assert result["vulnerable"] is True

    def test_command_not_found_detected(self, cmdi):
        resp = make_response(text="/bin/bash: invalid_cmd: command not found")
        result = cmdi.analyze_response(resp, ";invalid_cmd", "q", expected_sig="uid=")
        assert result["vulnerable"] is True

    def test_clean_response_not_flagged(self, cmdi):
        resp = make_response(text="<html>Search results for: test</html>")
        result = cmdi.analyze_response(resp, ";id", "q", expected_sig="uid=")
        assert result["vulnerable"] is False

    def test_result_has_required_keys(self, cmdi):
        resp = make_response(text="ok")
        result = cmdi.analyze_response(resp, "test", "q")
        for key in ("payload", "param", "vulnerable", "evidence"):
            assert key in result
