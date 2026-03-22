"""
tests/conftest.py
-----------------
Shared pytest fixtures used across all test modules.
"""

import pytest
from unittest.mock import MagicMock, patch
from core.config import Config
from utils.request_handler import RequestHandler


def make_config(**kwargs) -> Config:
    """
    Build a minimal Config for testing.
    Any field can be overridden via kwargs.
    """
    defaults = dict(
        url="http://test.lab/?id=1",
        module="sqli",
        threads=2,
        timeout=5,
        verbose=False,
        dry_run=False,
        no_color=True,
        silent=True,
    )
    defaults.update(kwargs)
    return Config(**defaults)


def make_response(
    status_code: int = 200,
    text: str = "",
    headers: dict = None,
    url: str = "http://test.lab/?id=1",
) -> MagicMock:
    """
    Build a mock requests.Response object.
    """
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode("utf-8")
    resp.headers = headers or {}
    resp.url = url
    resp.elapsed = MagicMock()
    resp.elapsed.total_seconds.return_value = 0.1
    return resp


@pytest.fixture
def config():
    return make_config()


@pytest.fixture
def mock_http(config):
    """Return a mock RequestHandler."""
    http = MagicMock(spec=RequestHandler)
    http.get.return_value = make_response(status_code=200, text="<html>Normal response</html>")
    http.post.return_value = make_response(status_code=200, text="<html>Login failed</html>")
    return http
