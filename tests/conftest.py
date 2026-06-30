"""Shared pytest fixtures for the SocksBox test suite."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest

from socksbox.models import ProxyInfo


@pytest.fixture
def proxy_factory() -> Callable[..., ProxyInfo]:
    """Return a callable that builds ProxyInfo instances with sensible defaults."""

    def _make(
        link: str = "socks5://127.0.0.1:1080",
        protocol: str = "socks5",
        label: str = "default",
        outbound: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ProxyInfo:
        return ProxyInfo(
            link=link,
            protocol=protocol,
            label=label,
            outbound=outbound or {},
            **kwargs,
        )

    return _make


@pytest.fixture(scope="session")
def event_loop() -> Any:
    """Provide a single event loop for the test session for pytest-asyncio."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
