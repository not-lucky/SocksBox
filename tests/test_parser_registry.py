"""Tests for the private parser registry and ``parse_proxy_link`` dispatch."""
from __future__ import annotations

import pytest

from socksbox import parser
from socksbox.parser import _PARSERS, parse_proxy_link


SUPPORTED_SCHEMES = [
    ("vmess", "vmess://eyJhZGQiOiJzLnZtZXNzLmV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoidXVpZCJ9", "_parse_vmess"),
    ("vless", "vless://uuid@example.com:443", "_parse_vless"),
    ("ss", "ss://aes-256-gcm:pass@example.com:8388", "_parse_ss"),
    ("ssr", "ssr://c2VydmVyOjQ0MzphdXRoX2FlczoxMjM6dGxzMS4yX3RpY2tldF9hdXRoOpass", "_parse_ssr"),
    ("trojan", "trojan://pass@example.com:443", "_parse_trojan"),
    ("hysteria2", "hysteria2://pass@example.com:443", "_parse_hysteria2"),
    ("hy2", "hy2://pass@example.com:443", "_parse_hysteria2"),
    ("tuic", "tuic://uuid@example.com:443", "_parse_tuic"),
    ("http", "http://example.com:8080", "_parse_http_proxy"),
    ("https", "https://example.com:8443", "_parse_http_proxy"),
    ("socks5", "socks5://example.com:1080", "_parse_socks5"),
    ("wg", "wg://example.com:51820?private_key=abc&public_key=def", "_parse_wireguard"),
    ("naive+https", "naive+https://example.com:443", "_parse_naiveproxy"),
    ("naive+quic", "naive+quic://example.com:443", "_parse_naiveproxy"),
]


@pytest.mark.parametrize("scheme, link, parser_name", SUPPORTED_SCHEMES)
def test_parse_proxy_link_dispatches_to_registered_parser(scheme: str, link: str, parser_name: str) -> None:
    """``parse_proxy_link`` must delegate each supported scheme to its registered parser."""
    sentinel = ({"type": scheme}, scheme, scheme)

    def mock_parser(_link: str) -> tuple[dict, str, str]:
        return sentinel

    with pytest.MonkeyPatch().context() as mp:
        mp.setitem(parser._PARSERS, scheme, mock_parser)
        result = parse_proxy_link(link)

    assert result is sentinel


@pytest.mark.parametrize("link", [
    "unknown://example.com",
    "unsupported://user:pass@host:123",
    "not-a-link",
])
def test_parse_proxy_link_unknown_scheme_raises(link: str) -> None:
    """Unknown or missing schemes must raise ``ValueError`` with a helpful message."""
    with pytest.raises(ValueError, match="unsupported link type"):
        parse_proxy_link(link)


def test_parse_proxy_link_does_not_mutate_registry() -> None:
    """Parsing links must not modify the private parser registry."""
    original = _PARSERS.copy()

    for _, link, _ in SUPPORTED_SCHEMES:
        # Invalid payload is fine here; we only care that the registry is unchanged.
        try:
            parse_proxy_link(link)
        except ValueError:
            pass

    assert _PARSERS == original
    assert list(_PARSERS.keys()) == list(original.keys())


def test_registry_is_private_and_covers_all_schemes() -> None:
    """The registry must be underscore-prefixed and contain every scheme handled by the parser."""
    assert hasattr(parser, "_PARSERS")
    assert not hasattr(parser, "PARSERS")
    assert isinstance(_PARSERS, dict)

    expected_schemes = {scheme for scheme, _, _ in SUPPORTED_SCHEMES}
    assert set(_PARSERS.keys()) == expected_schemes


def test_registry_is_not_mutated_by_callers() -> None:
    """Callers that copy the registry can extend their copy without affecting the module."""
    snapshot = dict(_PARSERS)
    caller_registry = _PARSERS.copy()
    caller_registry["custom"] = lambda link: ({}, "", "")

    assert _PARSERS == snapshot
    assert "custom" not in _PARSERS
