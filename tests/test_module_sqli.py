"""
tests/test_module_sqli.py
-------------------------
Unit tests for modules/sqli.py — SQLiModule.

Tests focus on analyze_response() and load_payloads() since
execute() requires network I/O (covered by integration tests).
"""

import pytest
from unittest.mock import MagicMock
from modules.sqli import SQLiModule
from tests.conftest import make_config, make_response


@pytest.fixture
def sqli(mock_http):
    cfg = make_config(module="sqli")
    return SQLiModule(cfg, mock_http)


class TestSQLiLoadPayloads:
    """Test payload loading."""

    def test_default_payloads_not_empty(self, sqli):
        payloads = sqli.load_payloads()
        assert len(payloads) > 0

    def test_default_payloads_contains_basic_quote(self, sqli):
        payloads = sqli.load_payloads()
        assert "'" in payloads

    def test_default_payloads_contains_union(self, sqli):
        payloads = sqli.load_payloads()
        assert any("UNION" in p.upper() for p in payloads)

    def test_external_wordlist_loaded(self, tmp_path, mock_http):
        wl = tmp_path / "sqli.txt"
        wl.write_text("custom_payload_1\ncustom_payload_2\n# comment\n\n")
        cfg = make_config(module="sqli", wordlist=str(wl))
        module = SQLiModule(cfg, mock_http)
        payloads = module.load_payloads()
        assert "custom_payload_1" in payloads
        assert "custom_payload_2" in payloads
        assert "# comment" not in payloads

    def test_missing_wordlist_returns_empty(self, mock_http):
        cfg = make_config(module="sqli", wordlist="/nonexistent/file.txt")
        module = SQLiModule(cfg, mock_http)
        payloads = module.load_payloads()
        assert payloads == []


class TestSQLiAnalyzeResponse:
    """Test the SQL error detection logic."""

    def test_mysql_error_detected(self, sqli):
        resp = make_response(text="You have an error in your sql syntax near '1' at line 1")
        result = sqli.analyze_response(resp, "'", "id")
        assert result["vulnerable"] is True
        assert "SQL error" in result["evidence"]

    def test_ora_error_detected(self, sqli):
        resp = make_response(text="ORA-00907: missing right parenthesis")
        result = sqli.analyze_response(resp, "'", "id")
        assert result["vulnerable"] is True

    def test_clean_response_not_flagged(self, sqli):
        resp = make_response(text="<html><body>Welcome!</body></html>")
        baseline = {"status": 200, "length": len("<html><body>Welcome!</body></html>"), "body": ""}
        result = sqli.analyze_response(resp, "1", "id", baseline)
        assert result["vulnerable"] is False

    def test_length_delta_flags_vuln(self, sqli):
        original = "A" * 100
        injected = "B" * 200   # 100% delta
        baseline = {"status": 200, "length": len(original), "body": original}
        resp = make_response(text=injected)
        result = sqli.analyze_response(resp, "' OR '1'='1", "id", baseline)
        assert result["vulnerable"] is True
        assert "delta" in result["evidence"].lower()

    def test_500_on_injection_flags_vuln(self, sqli):
        baseline = {"status": 200, "length": 500, "body": ""}
        resp = make_response(status_code=500, text="Internal Server Error")
        result = sqli.analyze_response(resp, "'", "id", baseline)
        assert result["vulnerable"] is True

    def test_result_contains_required_keys(self, sqli):
        resp = make_response(text="normal response")
        result = sqli.analyze_response(resp, "test", "id")
        for key in ("payload", "param", "vulnerable", "evidence"):
            assert key in result

    def test_warning_mysql_detected(self, sqli):
        resp = make_response(text="warning: mysql_fetch_array() expects parameter 1")
        result = sqli.analyze_response(resp, "'", "id")
        assert result["vulnerable"] is True

    def test_sqlite_error_detected(self, sqli):
        resp = make_response(text="sqlite3.OperationalError: near 'OR': syntax error")
        result = sqli.analyze_response(resp, "'", "id")
        assert result["vulnerable"] is True
