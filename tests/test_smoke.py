"""Smoke test to verify the test harness and fixtures work."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from socksbox.models import ProxyInfo


def test_proxy_factory(proxy_factory: Callable[..., ProxyInfo]) -> None:
    """proxy_factory should produce a ProxyInfo with the expected attributes."""
    proxy = proxy_factory()

    assert isinstance(proxy, ProxyInfo)
    assert proxy.link == "socks5://127.0.0.1:1080"
    assert proxy.protocol == "socks5"
    assert proxy.label == "default"
    assert proxy.outbound == {}
    assert proxy.working is False


def test_proxy_factory_overrides(proxy_factory: Callable[..., ProxyInfo]) -> None:
    """proxy_factory should accept and apply explicit field overrides."""
    proxy = proxy_factory(
        link="http://example.com:8080",
        protocol="http",
        label="test-label",
        outbound={"type": "http", "server": "example.com"},
        latency_ms=42.0,
        country="US",
    )

    assert proxy.link == "http://example.com:8080"
    assert proxy.protocol == "http"
    assert proxy.label == "test-label"
    assert proxy.outbound == {"type": "http", "server": "example.com"}
    assert proxy.latency_ms == 42.0
    assert proxy.working is True
    assert proxy.country == "US"
