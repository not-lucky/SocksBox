"""Tests for the SocksBox source adapter registry and CLI integration."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest

from socksbox.cli import load_sources
from socksbox.models import ProxyInfo
from socksbox.sources import DEFAULT_SOURCES, LoadResult, Source
from socksbox.sources.proxyscrape import DEFAULT_PROXYSCRAPE_SOURCE, ProxyscrapeSource
from socksbox.sources.shadowmere import DEFAULT_SHADOWMERE_SOURCE, ShadowmereSource
from socksbox.sources.url_text import DEFAULT_URL_TEXT_SOURCE, UrlTextSource


def _make_proxy(link: str = "socks5://127.0.0.1:1080", protocol: str = "socks5") -> ProxyInfo:
    return ProxyInfo(
        link=link,
        protocol=protocol,
        label="test",
        outbound={"type": protocol, "server": "127.0.0.1", "server_port": 1080},
    )


class FakeSource:
    """Conforming source adapter for injection into load_sources."""

    url: str = "fake://test"
    prints_summary: bool = False

    def __init__(self, result: LoadResult | None = None, exc: Exception | None = None) -> None:
        self.result = result or LoadResult(proxies=[], records=[])
        self.exc = exc
        self.calls: list[bool] = []

    def load(self, verify_ssl: bool = True) -> LoadResult:
        self.calls.append(verify_ssl)
        if self.exc is not None:
            raise self.exc
        return self.result


def test_registry_exports_source_protocol_and_load_result() -> None:
    assert Source is not None
    assert LoadResult is not None


def test_registry_contains_expected_adapters() -> None:
    assert len(DEFAULT_SOURCES) == 3
    assert DEFAULT_SOURCES[0] is DEFAULT_URL_TEXT_SOURCE
    assert DEFAULT_SOURCES[1] is DEFAULT_SHADOWMERE_SOURCE
    assert DEFAULT_SOURCES[2] is DEFAULT_PROXYSCRAPE_SOURCE


def test_default_adapters_satisfy_source_protocol() -> None:
    for source in DEFAULT_SOURCES:
        assert isinstance(source, Source)


def test_default_adapters_expose_source_urls() -> None:
    assert DEFAULT_URL_TEXT_SOURCE.url.startswith("https://github.com/ebrasha/")
    assert DEFAULT_SHADOWMERE_SOURCE.url == "https://shadowmere.xyz/api/sub/?format=json"
    assert DEFAULT_PROXYSCRAPE_SOURCE.url.startswith("https://api.proxyscrape.com/")


def test_url_text_adapter_labels_records(monkeypatch: Any) -> None:
    proxy = _make_proxy()
    monkeypatch.setattr(
        "socksbox.sources.url_text.parse_links_text",
        lambda text: ([proxy], [{"status": "ok"}]),
    )
    monkeypatch.setattr(
        "socksbox.sources.url_text.load_input",
        lambda source, verify_ssl=True: "some text",
    )

    source = UrlTextSource("https://example.com/list.txt")
    proxies, records = source.load()

    assert proxies == [proxy]
    assert records == [{"status": "ok", "source": "https://example.com/list.txt"}]


def test_url_text_adapter_preserves_existing_source_label(monkeypatch: Any) -> None:
    proxy = _make_proxy()
    monkeypatch.setattr(
        "socksbox.sources.url_text.parse_links_text",
        lambda text: ([proxy], [{"source": "existing", "status": "ok"}]),
    )
    monkeypatch.setattr(
        "socksbox.sources.url_text.load_input",
        lambda source, verify_ssl=True: "some text",
    )

    source = UrlTextSource("https://example.com/list.txt")
    proxies, records = source.load()

    assert records == [{"source": "existing", "status": "ok"}]


def test_shadowmere_adapter_labels_records(monkeypatch: Any) -> None:
    proxy = _make_proxy()
    monkeypatch.setattr(
        ShadowmereSource,
        "_parse",
        lambda self, data: ([proxy], [{"status": "ok"}]),
    )
    monkeypatch.setattr(
        ShadowmereSource,
        "_fetch",
        lambda self, verify_ssl=True: b"[]",
    )

    source = ShadowmereSource()
    proxies, records = source.load()

    assert proxies == [proxy]
    assert records == [{"status": "ok", "source": source.url}]


def test_proxyscrape_adapter_labels_records(monkeypatch: Any) -> None:
    proxy = _make_proxy()
    monkeypatch.setattr(
        ProxyscrapeSource,
        "_parse",
        lambda self, data: ([proxy], [{"status": "ok"}]),
    )
    monkeypatch.setattr(
        ProxyscrapeSource,
        "_fetch",
        lambda self, verify_ssl=True: b"{}",
    )

    source = ProxyscrapeSource()
    proxies, records = source.load()

    assert proxies == [proxy]
    assert records == [{"status": "ok", "source": source.url}]


def test_load_sources_uses_fake_adapter(monkeypatch: Any) -> None:
    proxy = _make_proxy()
    fake = FakeSource(result=LoadResult(proxies=[proxy], records=[{"status": "ok"}]))
    monkeypatch.setattr("socksbox.cli.DEFAULT_SOURCES", [fake])

    proxies, records, issues = load_sources()

    assert proxies == [proxy]
    assert records == [{"status": "ok", "source": "fake://test"}]
    assert issues == []
    assert fake.calls == [True]


def test_load_sources_applies_source_labels(monkeypatch: Any) -> None:
    proxy = _make_proxy()
    fake = FakeSource(
        result=LoadResult(
            proxies=[proxy],
            records=[{"status": "ok"}, {"status": "failed", "error": "bad"}],
        )
    )
    monkeypatch.setattr("socksbox.cli.DEFAULT_SOURCES", [fake])

    proxies, records, issues = load_sources()

    assert proxies == [proxy]
    assert records == [
        {"status": "ok", "source": "fake://test"},
        {"status": "failed", "error": "bad", "source": "fake://test"},
    ]
    assert issues == [{"status": "failed", "error": "bad", "source": "fake://test"}]


def test_load_sources_handles_empty_source(monkeypatch: Any, capsys: Any) -> None:
    fake = FakeSource(result=LoadResult(proxies=[], records=[]))
    fake.prints_summary = True
    monkeypatch.setattr("socksbox.cli.DEFAULT_SOURCES", [fake])

    proxies, records, issues = load_sources()

    assert proxies == []
    assert records == []
    assert issues == [
        {
            "source": "fake://test",
            "stage": "parse",
            "status": "failed",
            "kind": "empty_input",
            "error": "no valid proxies found",
        }
    ]
    captured = capsys.readouterr()
    assert "[skip] fake://test: no valid proxies found" in captured.err


def test_load_sources_handles_failing_source(monkeypatch: Any, capsys: Any) -> None:
    fake = FakeSource(exc=RuntimeError("boom"))
    fake.prints_summary = True
    monkeypatch.setattr("socksbox.cli.DEFAULT_SOURCES", [fake])

    proxies, records, issues = load_sources()

    assert proxies == []
    assert records == []
    assert len(issues) == 1
    assert issues[0]["source"] == "fake://test"
    assert issues[0]["stage"] == "load"
    assert "boom" in issues[0]["error"]
    assert "traceback" in issues[0]

    captured = capsys.readouterr()
    assert "[error] fake://test: boom" in captured.err


def test_load_sources_respects_verify_ssl(monkeypatch: Any) -> None:
    proxy = _make_proxy()
    fake = FakeSource(result=LoadResult(proxies=[proxy], records=[]))
    monkeypatch.setattr("socksbox.cli.DEFAULT_SOURCES", [fake])

    load_sources(verify_ssl=False)

    assert fake.calls == [False]


def test_load_sources_collects_from_multiple_sources(monkeypatch: Any) -> None:
    p1 = _make_proxy(link="socks5://1.2.3.4:1080")
    p2 = _make_proxy(link="socks5://5.6.7.8:1080")
    fake1 = FakeSource(result=LoadResult(proxies=[p1], records=[{"status": "ok"}]))
    fake1.url = "source1"
    fake2 = FakeSource(result=LoadResult(proxies=[p2], records=[{"status": "ok"}]))
    fake2.url = "source2"
    monkeypatch.setattr("socksbox.cli.DEFAULT_SOURCES", [fake1, fake2])

    proxies, records, issues = load_sources()

    assert proxies == [p1, p2]
    assert records == [
        {"status": "ok", "source": "source1"},
        {"status": "ok", "source": "source2"},
    ]
    assert issues == []


def test_load_sources_suppresses_summary_when_prints_summary_false(
    monkeypatch: Any, capsys: Any
) -> None:
    proxy = _make_proxy()
    fake = FakeSource(result=LoadResult(proxies=[proxy], records=[{"status": "ok"}]))
    fake.prints_summary = False
    monkeypatch.setattr("socksbox.cli.DEFAULT_SOURCES", [fake])

    proxies, _, _ = load_sources()

    assert proxies == [proxy]
    captured = capsys.readouterr()
    assert "[ok]" not in captured.err
    assert "[skip]" not in captured.err


def test_default_adapters_have_expected_prints_summary_flags() -> None:
    assert DEFAULT_URL_TEXT_SOURCE.prints_summary is True
    assert DEFAULT_SHADOWMERE_SOURCE.prints_summary is False
    assert DEFAULT_PROXYSCRAPE_SOURCE.prints_summary is False
