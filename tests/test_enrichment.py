import os
import json
import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import aiohttp

from socksbox.cli import load_env_file
from socksbox.config import AppConfig
from socksbox.models import ProxyInfo
from socksbox.enrichment import (
    BaseEnricher,
    GeoEnricher,
    PROVIDER_REGISTRY,
    EnrichmentProvider,
    IpInfoProvider,
    AbuseIPDBProvider,
)
from socksbox.enricher import enrich_proxy, enrich_proxies
from socksbox.exporters.json_exporter import DiagnosticsExporter
from socksbox.config_gen import generate_singbox_config


class DummyResponse:
    def __init__(self, status=200, text_data="{}", json_data=None):
        self.status = status
        self.text_data = text_data
        self.json_data = json_data or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    async def text(self):
        return self.text_data

    async def json(self):
        return self.json_data


class DummySession:
    def __init__(self, response=None):
        self.response = response or DummyResponse()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    def get(self, *args, **kwargs):
        return self.response


def test_load_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# This is a comment\n"
        "IPINFO_TOKEN=test-ipinfo-token\n"
        "ABUSEIPDB_TOKEN = \"test-abuse-token\"\n"
        "  SOME_OTHER_KEY = 'some_val' \n",
        encoding="utf-8"
    )

    with patch.dict(os.environ, {}):
        load_env_file(env_file)
        assert os.environ.get("IPINFO_TOKEN") == "test-ipinfo-token"
        assert os.environ.get("ABUSEIPDB_TOKEN") == "test-abuse-token"
        assert os.environ.get("SOME_OTHER_KEY") == "some_val"


def test_provider_registry() -> None:
    class DummyProvider(EnrichmentProvider):
        @property
        def name(self) -> str:
            return "dummy"
        async def enrich(self, *args: Any, **kwargs: Any) -> Any:
            return {"status": "dummy_ok"}
        def populate_proxy(self, proxy: ProxyInfo, response_data: dict[str, Any]) -> None:
            proxy.city = "DummyCity"

    provider = DummyProvider()
    PROVIDER_REGISTRY.register(provider)
    try:
        assert PROVIDER_REGISTRY.get("dummy") is provider
        assert provider in PROVIDER_REGISTRY.get_providers()
    finally:
        PROVIDER_REGISTRY.unregister("dummy")
        assert PROVIDER_REGISTRY.get("dummy") is None


@pytest.mark.asyncio
async def test_ipinfo_provider_success() -> None:
    proxy = ProxyInfo(link="socks5://127.0.0.1:1080", protocol="socks5", label="p1", outbound={})
    provider = IpInfoProvider()

    session = DummySession(DummyResponse(
        status=200,
        text_data='{"ip": "8.8.8.8", "country": "US", "city": "Mountain View"}'
    ))

    data = await provider.enrich(
        proxy,
        socks_port=10808,
        listen="127.0.0.1",
        token="test_token",
        timeout=5.0,
        session=session,
    )

    assert data == {"ip": "8.8.8.8", "country": "US", "city": "Mountain View"}
    provider.populate_proxy(proxy, data)
    assert proxy.ip == "8.8.8.8"
    assert proxy.country_code == "US"
    assert proxy.city == "Mountain View"


@pytest.mark.asyncio
async def test_ipinfo_provider_forbidden() -> None:
    proxy = ProxyInfo(link="socks5://127.0.0.1:1080", protocol="socks5", label="p1", outbound={})
    provider = IpInfoProvider()

    forbidden_body = (
        "Your client does not have permission to get URL <code>/json</code> from this server."
    )
    session = DummySession(DummyResponse(
        status=403,
        text_data=forbidden_body
    ))

    data = await provider.enrich(
        proxy,
        socks_port=10808,
        listen="127.0.0.1",
        token="test_token",
        timeout=5.0,
        session=session,
    )

    assert data is None
    assert proxy.working is False
    assert proxy.diagnostics["forbidden_check"]["reason"] == "ipinfo.io forbidden 403 response"


@pytest.mark.asyncio
async def test_abuseipdb_provider_success() -> None:
    proxy = ProxyInfo(link="socks5://127.0.0.1:1080", protocol="socks5", label="p1", outbound={})
    proxy.ip = "8.8.8.8"
    provider = AbuseIPDBProvider()

    session = DummySession(DummyResponse(
        status=200,
        json_data={
            "data": {
                "ipAddress": "8.8.8.8",
                "isPublic": True,
                "abuseConfidenceScore": 12,
                "countryCode": "US",
                "isp": "Google LLC"
            }
        }
    ))

    data = await provider.enrich(
        proxy,
        socks_port=10808,
        listen="127.0.0.1",
        token="test_token",
        timeout=5.0,
        session=session,
    )

    assert data is not None
    assert data["data"]["abuseConfidenceScore"] == 12
    provider.populate_proxy(proxy, data)
    assert proxy.org == "Google LLC"
    assert proxy.country_code == "US"


@pytest.mark.asyncio
async def test_custom_provider_enrich_flow() -> None:
    class FakeGeoProvider(EnrichmentProvider):
        @property
        def name(self) -> str:
            return "fakegeo"
        async def enrich(self, proxy, socks_port, listen, token, timeout, session, audit_log_path=None):
            return {"ip": "9.9.9.9", "country": "DE"}
        def populate_proxy(self, proxy, response_data):
            proxy.ip = response_data["ip"]
            proxy.country_code = response_data["country"]

    PROVIDER_REGISTRY.register(FakeGeoProvider())
    
    try:
        # ProxyInfo must have valid latency to be considered working
        proxy = ProxyInfo(link="socks5://127.0.0.1:1080", protocol="socks5", label="p1", outbound={}, latency_ms=10.0)
        
        with patch("socksbox.enrichment.enrichers.SocksConnector.from_url"):
            # Use DummySession to prevent real socket connection
            dummy_sess = DummySession()
            with patch("socksbox.enrichment.enrichers.aiohttp.ClientSession", return_value=dummy_sess):
                result = await enrich_proxy(
                    proxy,
                    socks_port=10808,
                    listen="127.0.0.1",
                    tokens={"fakegeo": "mytoken"},
                )
                
                assert result.ip == "9.9.9.9"
                assert result.country_code == "DE"
                assert isinstance(result.raw_geo, dict)
                assert result.raw_geo["fakegeo"] == {"ip": "9.9.9.9", "country": "DE"}
    finally:
        PROVIDER_REGISTRY.unregister("fakegeo")


@pytest.mark.asyncio
async def test_enrich_proxies_cycling() -> None:
    # Test that tokens are cycled per request
    proxy1 = ProxyInfo(link="socks5://127.0.0.1:1080", protocol="socks5", label="p1", outbound={}, latency_ms=10.0)
    proxy2 = ProxyInfo(link="socks5://127.0.0.1:1080", protocol="socks5", label="p2", outbound={}, latency_ms=12.0)
    
    called_tokens = []
    
    class TrackedProvider(EnrichmentProvider):
        @property
        def name(self) -> str:
            return "tracked"
        async def enrich(self, proxy, socks_port, listen, token, timeout, session, audit_log_path=None):
            called_tokens.append(token)
            return {"ok": True}
        def populate_proxy(self, proxy, response_data):
            pass

    PROVIDER_REGISTRY.register(TrackedProvider())
    
    try:
        with patch("socksbox.enrichment.enrichers.SocksConnector.from_url"):
            dummy_sess = DummySession()
            with patch("socksbox.enrichment.enrichers.aiohttp.ClientSession", return_value=dummy_sess):
                await enrich_proxies(
                    [proxy1, proxy2],
                    start_port=10808,
                    provider_tokens={"tracked": ["keyA", "keyB"]},
                )
                
                assert len(called_tokens) == 2
                assert set(called_tokens) == {"keyA", "keyB"}
    finally:
        PROVIDER_REGISTRY.unregister("tracked")


def test_diagnostics_exporter_saves_raw_geo(tmp_path: Path) -> None:
    proxy = ProxyInfo(link="socks5://127.0.0.1:1080", protocol="socks5", label="p1", outbound={}, latency_ms=15.0)
    proxy.raw_geo = {"ipinfo": {"ip": "1.1.1.1"}}
    
    exporter = DiagnosticsExporter()
    exporter.write([proxy], {}, tmp_path, 10808, [])
    
    diag_file = tmp_path / "diagnostics.json"
    assert diag_file.exists()
    
    data = json.loads(diag_file.read_text(encoding="utf-8"))
    proxy_data = data["proxies"][0]
    assert proxy_data["raw_geo"] == {"ipinfo": {"ip": "1.1.1.1"}}


@pytest.mark.asyncio
async def test_active_providers_filtering() -> None:
    # Test that only providers in active_providers are run
    proxy = ProxyInfo(link="socks5://127.0.0.1:1080", protocol="socks5", label="p1", outbound={}, latency_ms=10.0)
    
    called = []
    
    class ProvA(EnrichmentProvider):
        @property
        def name(self) -> str:
            return "prova"
        async def enrich(self, proxy, socks_port, listen, token, timeout, session, audit_log_path=None):
            called.append("prova")
            return {"ok": True}
        def populate_proxy(self, proxy, response_data):
            pass

    class ProvB(EnrichmentProvider):
        @property
        def name(self) -> str:
            return "provb"
        async def enrich(self, proxy, socks_port, listen, token, timeout, session, audit_log_path=None):
            called.append("provb")
            return {"ok": True}
        def populate_proxy(self, proxy, response_data):
            pass

    PROVIDER_REGISTRY.register(ProvA())
    PROVIDER_REGISTRY.register(ProvB())
    
    try:
        with patch("socksbox.enrichment.enrichers.SocksConnector.from_url"):
            dummy_sess = DummySession()
            with patch("socksbox.enrichment.enrichers.aiohttp.ClientSession", return_value=dummy_sess):
                await enrich_proxy(
                    proxy,
                    socks_port=10808,
                    listen="127.0.0.1",
                    active_providers=["prova"],  # Only provA is active!
                )
                
                assert "prova" in called
                assert "provb" not in called
    finally:
        PROVIDER_REGISTRY.unregister("prova")
        PROVIDER_REGISTRY.unregister("provb")


def test_generate_singbox_config_sorting() -> None:
    # 3 proxies:
    # proxy A: abuse 20, latency 10
    # proxy B: abuse 10, latency 50
    # proxy C: abuse 10, latency 30 (tie breaker should win over B)
    proxyA = ProxyInfo(
        link="socks5://127.0.0.1:1080", protocol="socks5", label="pA", outbound={"server": "srvA"}, latency_ms=10.0
    )
    proxyA.raw_geo = {"abuseipdb": {"data": {"abuseConfidenceScore": 20}}}
    
    proxyB = ProxyInfo(
        link="socks5://127.0.0.1:1081", protocol="socks5", label="pB", outbound={"server": "srvB"}, latency_ms=50.0
    )
    proxyB.raw_geo = {"abuseipdb": {"data": {"abuseConfidenceScore": 10}}}

    proxyC = ProxyInfo(
        link="socks5://127.0.0.1:1082", protocol="socks5", label="pC", outbound={"server": "srvC"}, latency_ms=30.0
    )
    proxyC.raw_geo = {"abuseipdb": {"data": {"abuseConfidenceScore": 10}}}

    config = generate_singbox_config([proxyA, proxyB, proxyC])
    
    # Expected order: proxyC (score 10, lat 30), proxyB (score 10, lat 50), proxyA (score 20, lat 10)
    outbounds = config["outbounds"]
    assert len(outbounds) == 3
    assert outbounds[0]["server"] == "srvC"
    assert outbounds[1]["server"] == "srvB"
    assert outbounds[2]["server"] == "srvA"
