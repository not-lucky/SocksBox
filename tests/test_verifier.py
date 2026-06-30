"""Tests for the proxy verifier and its runner integration."""

from __future__ import annotations

import subprocess
from typing import Any
from unittest.mock import MagicMock

import pytest

from socksbox.models import ProxyInfo
from socksbox.runner import FakeSingBoxRunner, SingBoxEndpoint, SubprocessSingBoxRunner
from socksbox.verifier import verify_proxies


class TestVerifyProxiesRunnerIntegration:
    @pytest.fixture
    def patch_sing_box_version(self, monkeypatch: Any) -> None:
        """Make ``sing-box version`` appear available."""

        def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

    @pytest.fixture
    def patch_sing_box_check(self, monkeypatch: Any) -> None:
        """Make ``sing-box check`` always succeed."""

        def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

    @pytest.fixture
    def patch_curl_check(self, monkeypatch: Any) -> None:
        """Make the ipinfo forbidden curl check return not-blocked."""

        async def fake_curl(*args: Any, **kwargs: Any) -> tuple[bool, int]:
            return False, 200

        monkeypatch.setattr(
            "socksbox.verifier.curl_ipinfo_forbidden_check",
            fake_curl,
        )

    @pytest.mark.asyncio
    async def test_uses_subprocess_runner_for_live_phase(
        self,
        proxy_factory: Any,
        monkeypatch: Any,
        patch_sing_box_version: None,
        patch_sing_box_check: None,
        patch_curl_check: None,
    ) -> None:
        proxy = proxy_factory(
            label="test-proxy",
            outbound={"type": "socks", "server": "127.0.0.1", "server_port": 1080},
        )

        captured: dict[str, Any] = {}

        async def fake_measure(listen: str, port: int, **kwargs: Any) -> tuple[float, dict[str, Any]]:
            captured["listen"] = listen
            captured["port"] = port
            return 42.0, {"status": "ok"}

        monkeypatch.setattr("socksbox.verifier.measure_proxy_average_latency", fake_measure)

        # Patch SubprocessSingBoxRunner so no real process is spawned.
        class PatchedRunner(SubprocessSingBoxRunner):
            async def __aenter__(self) -> SingBoxEndpoint:
                captured["runner_config"] = self.config
                captured["runner_listen"] = self.listen
                captured["runner_start_port"] = self.start_port
                return SingBoxEndpoint(listen=self.listen, start_port=self.start_port)

            async def __aexit__(self, *args: Any) -> None:
                return None

        monkeypatch.setattr("socksbox.verifier.SubprocessSingBoxRunner", PatchedRunner)

        result = await verify_proxies([proxy], start_port=15000, listen="127.0.0.1")

        assert result[0].latency_ms == 42.0
        assert captured["listen"] == "127.0.0.1"
        assert captured["port"] == 15000
        assert captured["runner_listen"] == "127.0.0.1"
        assert captured["runner_start_port"] == 15000
        assert captured["runner_config"]["inbounds"][0]["listen"] == "127.0.0.1"
        assert captured["runner_config"]["inbounds"][0]["listen_port"] == 15000

    @pytest.mark.asyncio
    async def test_maps_ports_after_removing_incompatible_proxies(
        self,
        proxy_factory: Any,
        monkeypatch: Any,
        patch_curl_check: None,
    ) -> None:
        good = proxy_factory(label="good", outbound={"type": "socks", "server": "127.0.0.1", "server_port": 1080})
        bad = proxy_factory(label="bad", outbound={"type": "invalid", "server": "127.0.0.1", "server_port": 1081})

        call_count = {"check": 0}

        def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
            if cmd[1] == "version":
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            # First sing-box check fails because the second outbound is invalid.
            call_count["check"] += 1
            if call_count["check"] == 1:
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=1,
                    stdout="",
                    stderr=" outbound[1]: unsupported outbound type invalid",
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        measured_ports: list[int] = []

        async def fake_measure(listen: str, port: int, **kwargs: Any) -> tuple[float, dict[str, Any]]:
            measured_ports.append(port)
            return 10.0, {"status": "ok"}

        monkeypatch.setattr("socksbox.verifier.measure_proxy_average_latency", fake_measure)

        class PatchedRunner(SubprocessSingBoxRunner):
            async def __aenter__(self) -> SingBoxEndpoint:
                return SingBoxEndpoint(listen="127.0.0.1", start_port=15000)

            async def __aexit__(self, *args: Any) -> None:
                return None

        monkeypatch.setattr("socksbox.verifier.SubprocessSingBoxRunner", PatchedRunner)

        proxies = [good, bad]
        result = await verify_proxies(proxies, start_port=15000, listen="127.0.0.1")

        assert result[0].latency_ms == 10.0
        assert result[1].latency_ms == float("inf")
        assert measured_ports == [15000]

    @pytest.mark.asyncio
    async def test_returns_proxies_when_runner_dies_early(
        self,
        proxy_factory: Any,
        monkeypatch: Any,
        patch_sing_box_version: None,
        patch_sing_box_check: None,
    ) -> None:
        proxy = proxy_factory(label="test", outbound={"type": "socks", "server": "127.0.0.1", "server_port": 1080})

        class FailingRunner(SubprocessSingBoxRunner):
            async def __aenter__(self) -> SingBoxEndpoint:
                raise RuntimeError("sing-box terminated early during startup")

            async def __aexit__(self, *args: Any) -> None:
                return None

        monkeypatch.setattr("socksbox.verifier.SubprocessSingBoxRunner", FailingRunner)

        result = await verify_proxies([proxy], start_port=15000)

        assert result[0] is proxy
        assert result[0].latency_ms == float("inf")

    @pytest.mark.asyncio
    async def test_returns_empty_list_when_given_no_proxies(self) -> None:
        result = await verify_proxies([])
        assert result == []
