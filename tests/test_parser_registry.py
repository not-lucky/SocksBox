"""Tests for the ParserRegistry (Flyweight + Strategy patterns) and ``parse_proxy_link`` dispatch."""
from __future__ import annotations

import pytest

from socksbox.parsing.registry import GLOBAL_REGISTRY, ParserRegistry
from socksbox.parsing.base import ParserStrategy


SUPPORTED_SCHEMES = [
    ("vmess", "vmess://eyJhZGQiOiJzLnZtZXNzLmV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoidXVpZCJ9"),
    ("vless", "vless://uuid@example.com:443"),
    ("ss", "ss://aes-256-gcm:pass@example.com:8388"),
    ("ssr", "ssr://c2VydmVyOjQ0MzphdXRoX2FlczoxMjM6dGxzMS4yX3RpY2tldF9hdXRoOpass"),
    ("trojan", "trojan://pass@example.com:443"),
    ("hysteria2", "hysteria2://pass@example.com:443"),
    ("hy2", "hy2://pass@example.com:443"),
    ("tuic", "tuic://uuid@example.com:443"),
    ("http", "http://example.com:8080"),
    ("https", "https://example.com:8443"),
    ("socks5", "socks5://example.com:1080"),
    ("wg", "wg://example.com:51820?private_key=abc&public_key=def"),
    ("naive+https", "naive+https://example.com:443"),
    ("naive+quic", "naive+quic://example.com:443"),
]


class MockParser:
    def __init__(self, schemes: tuple[str, ...]) -> None:
        self._schemes = schemes

    @property
    def schemes(self) -> tuple[str, ...]:
        return self._schemes

    def parse(self, link: str) -> tuple[dict, str, str]:
        return ({"type": self._schemes[0]}, self._schemes[0], self._schemes[0])


@pytest.mark.parametrize("scheme, link", SUPPORTED_SCHEMES)
def test_parse_proxy_link_dispatches_to_registered_parser(scheme: str, link: str) -> None:
    """``parse_proxy_link`` must delegate each supported scheme to its registered parser strategy."""
    registry = ParserRegistry()
    mock_parser = MockParser((scheme,))
    registry.register(mock_parser)

    result = registry.parse_proxy_link(link)
    assert result == ({"type": scheme}, scheme, scheme)


@pytest.mark.parametrize("link", [
    "unknown://example.com",
    "unsupported://user:pass@host:123",
    "not-a-link",
])
def test_parse_proxy_link_unknown_scheme_raises(link: str) -> None:
    """Unknown or missing schemes must raise ``ValueError`` with a helpful message."""
    registry = ParserRegistry()
    with pytest.raises(ValueError, match="unsupported link type"):
        registry.parse_proxy_link(link)


def test_registry_contains_all_default_parsers() -> None:
    """The global registry should contain all expected schemes."""
    expected_schemes = {scheme for scheme, _ in SUPPORTED_SCHEMES}
    assert expected_schemes.issubset(set(GLOBAL_REGISTRY._parsers.keys()))
