"""
tests/test_config.py
--------------------
Unit tests for core/config.py — Config dataclass and YAML profile loading.
"""

import pytest
import tempfile
import os
from core.config import Config
from tests.conftest import make_config


class TestConfigDefaults:
    """Test that Config initialises with correct default values."""

    def test_required_fields(self):
        cfg = make_config(url="http://target.lab/?id=1", module="sqli")
        assert cfg.url == "http://target.lab/?id=1"
        assert cfg.module == "sqli"

    def test_fixture_threads_override(self):
        # make_config sets threads=2 for fast test runs — this verifies the fixture, not the class default.
        cfg = make_config()
        assert cfg.threads == 2

    def test_class_default_threads(self):
        # Instantiate Config directly to verify the real default is 5.
        cfg = Config(url="http://target.lab/?id=1", module="sqli")
        assert cfg.threads == 5

    def test_default_timeout(self):
        cfg = make_config()
        assert cfg.timeout == 5

    def test_default_proxy_is_none(self):
        cfg = make_config()
        assert cfg.proxy is None

    def test_default_headers_empty(self):
        cfg = make_config()
        assert cfg.headers == {}

    def test_default_cookies_empty(self):
        cfg = make_config()
        assert cfg.cookies == {}

    def test_default_dry_run_false(self):
        cfg = make_config()
        assert cfg.dry_run is False

    def test_default_verbose_false(self):
        cfg = make_config()
        assert cfg.verbose is False

    def test_default_output_format_json(self):
        cfg = make_config()
        assert cfg.output_format == "json"

    def test_default_payload_encoding_none(self):
        cfg = make_config()
        assert cfg.payload_encoding == "none"


class TestProxyDict:
    """Test Config.proxy_dict() helper."""

    def test_proxy_dict_none_when_no_proxy(self):
        cfg = make_config()
        assert cfg.proxy_dict() is None

    def test_proxy_dict_returns_both_protocols(self):
        cfg = make_config(proxy="http://127.0.0.1:8080")
        proxy = cfg.proxy_dict()
        assert proxy is not None
        assert proxy["http"] == "http://127.0.0.1:8080"
        assert proxy["https"] == "http://127.0.0.1:8080"


class TestUserAgent:
    """Test Config.effective_user_agent()."""

    def test_default_user_agent_contains_mozilla(self):
        cfg = make_config()
        ua = cfg.effective_user_agent()
        assert "Mozilla" in ua

    def test_custom_user_agent_returned(self):
        cfg = make_config(user_agent="CustomBot/1.0")
        assert cfg.effective_user_agent() == "CustomBot/1.0"


class TestToDict:
    """Test Config.to_dict() serialisation."""

    def test_to_dict_returns_dict(self):
        cfg = make_config()
        d = cfg.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_contains_url(self):
        cfg = make_config(url="http://example.com/?q=1")
        d = cfg.to_dict()
        assert d["url"] == "http://example.com/?q=1"

    def test_to_dict_contains_module(self):
        cfg = make_config(module="xss")
        d = cfg.to_dict()
        assert d["module"] == "xss"


class TestYAMLProfile:
    """Test Config.from_yaml() profile loading."""

    def _write_profile(self, content: str) -> str:
        """Write a temp YAML file and return its path."""
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        )
        f.write(content)
        f.close()
        return f.name

    def test_load_basic_profile(self):
        path = self._write_profile(
            "url: http://target.lab/?id=1\nmodule: sqli\n"
        )
        try:
            cfg = Config.from_yaml(path)
            assert cfg.url == "http://target.lab/?id=1"
            assert cfg.module == "sqli"
        finally:
            os.unlink(path)

    def test_profile_with_threads(self):
        path = self._write_profile(
            "url: http://t.lab/\nmodule: xss\nthreads: 20\n"
        )
        try:
            cfg = Config.from_yaml(path)
            assert cfg.threads == 20
        finally:
            os.unlink(path)

    def test_cli_override_beats_profile(self):
        path = self._write_profile(
            "url: http://t.lab/\nmodule: sqli\nthreads: 5\n"
        )
        try:
            cfg = Config.from_yaml(path, overrides={"threads": 99})
            assert cfg.threads == 99
        finally:
            os.unlink(path)

    def test_missing_profile_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            Config.from_yaml("/nonexistent/profile.yaml")

    def test_missing_required_field_raises_value_error(self):
        path = self._write_profile("url: http://t.lab/\n")   # no module
        try:
            with pytest.raises(ValueError, match="module"):
                Config.from_yaml(path)
        finally:
            os.unlink(path)

    def test_unknown_yaml_fields_ignored(self):
        """Extra fields in YAML that don't match Config fields should be silently dropped."""
        path = self._write_profile(
            "url: http://t.lab/\nmodule: lfi\nfake_field: should_be_ignored\n"
        )
        try:
            cfg = Config.from_yaml(path)
            assert cfg.module == "lfi"
            assert not hasattr(cfg, "fake_field")
        finally:
            os.unlink(path)
