import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakeapis import FakeAPIs  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


@pytest.fixture
def fix():
    """Path to a fixture project directory: fix('uv')."""
    return lambda name: os.path.join(FIX, name)


@pytest.fixture
def fake():
    api = FakeAPIs().start()
    yield api
    api.stop()


@pytest.fixture
def offline(fake, monkeypatch):
    """Point the server module at the fake APIs with fresh caches."""
    from depaudit_mcp import server
    from depaudit_mcp.http import Http
    from depaudit_mcp.osv import OSV
    from depaudit_mcp.registry import Registry

    for k, v in fake.env().items():
        monkeypatch.setenv(k, v)
    http = Http(sleep=lambda s: None)
    monkeypatch.setattr(server, "_osv", OSV(http))
    monkeypatch.setattr(server, "_registry", Registry(http))
    return fake


@pytest.fixture
def anyio_backend():
    return "asyncio"
