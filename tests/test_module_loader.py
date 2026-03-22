"""
tests/test_module_loader.py
----------------------------
Unit tests for core/module_loader.py — plugin architecture.
"""

import pytest
from core.module_loader import load_module, list_modules
from modules.sqli import SQLiModule
from modules.xss import XSSModule
from modules.lfi import LFIModule
from modules.auth import AuthModule
from modules.ssrf import SSRFModule
from modules.redirect import OpenRedirectModule
from modules.idor import IDORModule
from modules.cmdi import CMDiModule


class TestListModules:

    def test_returns_list(self):
        modules = list_modules()
        assert isinstance(modules, list)

    def test_all_expected_modules_present(self):
        modules = list_modules()
        for name in ("sqli", "xss", "lfi", "auth", "ssrf", "redirect", "idor", "cmdi"):
            assert name in modules

    def test_returns_at_least_eight_modules(self):
        assert len(list_modules()) >= 8


class TestLoadModule:

    @pytest.mark.parametrize("name,expected_class", [
        ("sqli",     SQLiModule),
        ("xss",      XSSModule),
        ("lfi",      LFIModule),
        ("auth",     AuthModule),
        ("ssrf",     SSRFModule),
        ("redirect", OpenRedirectModule),
        ("idor",     IDORModule),
        ("cmdi",     CMDiModule),
    ])
    def test_load_known_module(self, name, expected_class):
        cls = load_module(name)
        assert cls is expected_class

    def test_unknown_module_returns_none(self):
        cls = load_module("nonexistent_module_xyz")
        assert cls is None

    def test_loaded_class_is_instantiable(self):
        """Verify the loaded class can be instantiated with config + http mock."""
        from unittest.mock import MagicMock
        from tests.conftest import make_config
        cls = load_module("sqli")
        cfg = make_config(module="sqli")
        http = MagicMock()
        instance = cls(cfg, http)
        assert instance is not None

    def test_loaded_class_has_execute_method(self):
        cls = load_module("xss")
        assert hasattr(cls, "execute")

    def test_loaded_class_has_load_payloads_method(self):
        cls = load_module("lfi")
        assert hasattr(cls, "load_payloads")

    def test_loaded_class_has_analyze_response_method(self):
        cls = load_module("sqli")
        assert hasattr(cls, "analyze_response")
