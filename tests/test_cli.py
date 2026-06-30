"""Tests for CLI orchestration helpers."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest

from socksbox.cli import enrich_with_live_sing_box
from socksbox.models import ProxyInfo
from socksbox.runner import FakeSingBoxRunner, SingBoxEndpoint


class _SpyRunner:
    """Stand-in for SubprocessSingBoxRunner that records construction args."""

    def __init__(
        self,
        config: dict[str, Any],
        *,
        sing_box: str = "sing-box",
        listen: str = "127.0.0.1",
        start_port: int = 10808,
        startup_delay: float = 2.0,
    ) -> None:
        self.config = config
        self.sing_box = sing_box
        self.listen = listen
        self.start_port = start_port
        self.startup_delay = startup_delay
        self._endpoint = SingBoxEndpoint(listen=listen, start_port=start_port)

    async def __aenter__(self) -> SingBoxEndpoint:
        return self._endpoint

    async def __aexit__(self, *args: Any, **kwargs: Any) -> None:
        return None


@pytest.fixture
def async_enrich_mock(monkeypatch: Any) -> MagicMock:
    """Replace enrich_proxies with an async mock that returns its input."""

    async def _enrich(proxies: list[ProxyInfo], **kwargs: Any) -> list[ProxyInfo]:
        return proxies

    mock = MagicMock(side_effect=_enrich)
    monkeypatch.setattr("socksbox.cli.enrich_proxies", mock)
    return mock


@pytest.mark.asyncio
async def test_enrich_skips_when_no_working_proxies(
    proxy_factory: Callable[..., ProxyInfo],
    monkeypatch: Any,
    async_enrich_mock: MagicMock,
) -> None:
    """enrich_with_live_sing_box should short-circuit if no proxies are working."""
    spy_class = MagicMock(side_effect=Exception("runner should not be instantiated"))
    monkeypatch.setattr("socksbox.cli.SubprocessSingBoxRunner", spy_class)

    proxies = [proxy_factory(), proxy_factory()]
    result = await enrich_with_live_sing_box(
        proxies,
        start_port=10808,
        listen="127.0.0.1",
        sing_box="sing-box",
        concurrency=10,
        tokens=None,
        verbose=False,
    )

    assert result is proxies
    spy_class.assert_not_called()
    async_enrich_mock.assert_not_called()


@pytest.mark.asyncio
async def test_enrich_uses_runner_and_passes_endpoint_to_enricher(
    proxy_factory: Callable[..., ProxyInfo],
    monkeypatch: Any,
    async_enrich_mock: MagicMock,
) -> None:
    """enrich_with_live_sing_box should delegate subprocess lifecycle to the runner."""
    spy_runner = MagicMock(wraps=_SpyRunner)
    monkeypatch.setattr("socksbox.cli.SubprocessSingBoxRunner", spy_runner)

    working = proxy_factory(
        link="socks5://127.0.0.1:1080",
        protocol="socks5",
        label="w1",
        latency_ms=100.0,
    )
    failed = proxy_factory()
    proxies = [working, failed]

    result = await enrich_with_live_sing_box(
        proxies,
        start_port=10808,
        listen="127.0.0.1",
        sing_box="sing-box",
        concurrency=10,
        tokens=None,
        verbose=False,
        audit_log_path=None,
    )

    assert result is proxies
    spy_runner.assert_called_once()
    call_kwargs = spy_runner.call_args.kwargs
    assert call_kwargs["sing_box"] == "sing-box"
    assert call_kwargs["listen"] == "127.0.0.1"
    assert call_kwargs["start_port"] == 10808
    assert call_kwargs["startup_delay"] == 2.0

    config = spy_runner.call_args.args[0]
    assert "inbounds" in config

    async_enrich_mock.assert_called_once()
    enrich_kwargs = async_enrich_mock.call_args.kwargs
    assert enrich_kwargs["start_port"] == 10808
    assert enrich_kwargs["listen"] == "127.0.0.1"
    assert enrich_kwargs["concurrency"] == 10
    assert enrich_kwargs["tokens"] is None
    assert enrich_kwargs["verbose"] is False


@pytest.mark.asyncio
async def test_enrich_forwards_custom_endpoint_from_runner(
    proxy_factory: Callable[..., ProxyInfo],
    monkeypatch: Any,
    async_enrich_mock: MagicMock,
) -> None:
    """Endpoint values from the runner should flow into enrich_proxies."""
    monkeypatch.setattr(
        "socksbox.cli.SubprocessSingBoxRunner",
        lambda *args, **kwargs: FakeSingBoxRunner(listen="10.0.0.1", start_port=20000),
    )

    proxies = [proxy_factory(latency_ms=50.0)]
    await enrich_with_live_sing_box(
        proxies,
        start_port=10808,
        listen="127.0.0.1",
        sing_box="sing-box",
        concurrency=5,
        tokens=None,
        verbose=False,
    )

    enrich_kwargs = async_enrich_mock.call_args.kwargs
    assert enrich_kwargs["start_port"] == 20000
    assert enrich_kwargs["listen"] == "10.0.0.1"
