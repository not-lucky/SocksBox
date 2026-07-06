"""Tests for socksbox.sources.base."""

from __future__ import annotations

from typing import Any, get_type_hints

import pytest

from socksbox.models import ProxyInfo
from socksbox.sources.base import LoadResult, Source


def _dummy_proxy() -> ProxyInfo:
    return ProxyInfo(
        link="socks5://127.0.0.1:1080",
        protocol="socks5",
        label="dummy",
        outbound={"type": "socks", "server": "127.0.0.1", "server_port": 1080},
    )


class _DummySource:
    """Minimal source implementation for protocol/runtime checks."""

    url: str = "dummy"
    prints_summary: bool = True

    def load(self, verify_ssl: bool = True) -> LoadResult:
        return LoadResult(proxies=[_dummy_proxy()], records=[{"source": "dummy"}])


class _MissingLoad:
    """Class that does not satisfy the Source protocol."""

    pass


class _WrongSignature:
    """Class with a load method that has the wrong parameter name."""

    def load(self, verify_tls: bool = True) -> LoadResult:  # type: ignore[override]
        return LoadResult(proxies=[], records=[])


def test_load_result_exposes_named_fields() -> None:
    proxies = [_dummy_proxy()]
    records: list[dict[str, Any]] = [{"source": "dummy", "stage": "parse"}]
    result = LoadResult(proxies=proxies, records=records)

    assert result.proxies is proxies
    assert result.records is records


def test_load_result_unpacks_like_tuple() -> None:
    proxies = [_dummy_proxy()]
    records: list[dict[str, Any]] = [{"status": "ok"}]
    result = LoadResult(proxies=proxies, records=records)

    unpacked_proxies, unpacked_records = result

    assert unpacked_proxies is proxies
    assert unpacked_records is records


def test_load_result_is_frozen() -> None:
    result = LoadResult(proxies=[], records=[])

    with pytest.raises(AttributeError):
        result.proxies = [_dummy_proxy()]


def test_load_result_repr_shows_class_and_field_counts() -> None:
    result = LoadResult(proxies=[_dummy_proxy()], records=[{"status": "ok"}])
    text = repr(result)
    assert text.startswith("LoadResult(")
    assert "proxies=[" in text
    assert "records=[" in text


def test_source_protocol_accepts_conforming_implementation() -> None:
    source = _DummySource()
    assert isinstance(source, Source)


def test_source_protocol_rejects_missing_load() -> None:
    assert not isinstance(_MissingLoad(), Source)


def test_source_protocol_load_return_type() -> None:
    hints = get_type_hints(Source.load)
    assert hints["return"] is LoadResult


def test_dummy_source_load_produces_expected_shape() -> None:
    source = _DummySource()
    proxies, records = source.load(verify_ssl=True)

    assert len(proxies) == 1
    assert proxies[0].protocol == "socks5"
    assert records == [{"source": "dummy"}]


def test_source_protocol_signature_includes_verify_ssl() -> None:
    hints = get_type_hints(Source.load)
    assert "verify_ssl" in hints
    assert hints["verify_ssl"] is bool
