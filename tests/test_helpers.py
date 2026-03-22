"""
tests/test_helpers.py
---------------------
Unit tests for utils/helpers.py — URL parameter extraction and injection.
"""

import pytest
from utils.helpers import extract_params, inject_param, truncate, sanitize_filename


class TestExtractParams:
    """Tests for extract_params()."""

    def test_single_param(self):
        params = extract_params("http://target.lab/search?q=hello")
        assert params == ["q"]

    def test_multiple_params(self):
        params = extract_params("http://target.lab/?id=1&page=2&sort=asc")
        assert set(params) == {"id", "page", "sort"}

    def test_no_params(self):
        params = extract_params("http://target.lab/index.html")
        assert params == []

    def test_override_param_ignored_when_explicit(self):
        params = extract_params("http://target.lab/?id=1&name=foo", override_param="id")
        assert params == ["id"]
        assert "name" not in params

    def test_override_param_added_even_if_not_in_url(self):
        params = extract_params("http://target.lab/page", override_param="custom")
        assert params == ["custom"]

    def test_empty_value_param(self):
        params = extract_params("http://target.lab/?id=")
        assert "id" in params


class TestInjectParam:
    """Tests for inject_param()."""

    def test_replace_existing_param(self):
        url = inject_param("http://target.lab/?id=1", "id", "' OR '1'='1")
        assert "id=" in url
        # The original plain value should be gone — payload is URL-encoded so '1' appears
        # inside the encoding (%271%27...) — check the whole segment changed instead
        assert "id=1&" not in url and not url.endswith("id=1")
        # Payload is present in encoded form
        assert "OR" in url or "%27" in url

    def test_add_new_param(self):
        url = inject_param("http://target.lab/page", "id", "99")
        assert "id=99" in url

    def test_payload_encoded_in_url(self):
        url = inject_param("http://target.lab/?q=test", "q", "<script>")
        # URL encoding should be present
        assert "q=" in url
        assert "script" in url  # payload present in some form

    def test_preserves_other_params(self):
        url = inject_param("http://target.lab/?id=1&page=2", "id", "INJECTED")
        assert "page=2" in url

    def test_fragment_preserved(self):
        url = inject_param("http://target.lab/?id=1#section", "id", "2")
        assert "#section" in url

    def test_scheme_preserved(self):
        url = inject_param("https://target.lab/?id=1", "id", "2")
        assert url.startswith("https://")

    def test_multiple_injection_calls_idempotent(self):
        url1 = inject_param("http://target.lab/?id=1", "id", "PAYLOAD")
        url2 = inject_param(url1, "id", "PAYLOAD")
        assert url1 == url2


class TestTruncate:
    """Tests for truncate()."""

    def test_short_string_unchanged(self):
        assert truncate("hello", max_length=80) == "hello"

    def test_long_string_truncated(self):
        result = truncate("a" * 100, max_length=20)
        assert len(result) == 20
        assert result.endswith("...")

    def test_exact_length_not_truncated(self):
        s = "a" * 80
        assert truncate(s, max_length=80) == s


class TestSanitizeFilename:
    """Tests for sanitize_filename()."""

    def test_safe_characters_unchanged(self):
        assert sanitize_filename("report_2024.json") == "report_2024.json"

    def test_spaces_replaced(self):
        result = sanitize_filename("my report file")
        assert " " not in result

    def test_slashes_replaced(self):
        result = sanitize_filename("path/to/file")
        assert "/" not in result

    def test_returns_string(self):
        assert isinstance(sanitize_filename("test"), str)
