"""Tests for download verification and its runner integration."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from socksbox.downloader import run_download_verification
from socksbox.runner import SingBoxEndpoint, SubprocessSingBoxRunner


@pytest.fixture
def patch_sing_box_version(monkeypatch: Any) -> None:
    """Make ``sing-box version`` appear available."""

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)


@pytest.fixture
def make_capture_runner(monkeypatch: Any) -> Any:
    """Return a factory that installs a capturing stub for SubprocessSingBoxRunner."""

    def _install(listen: str = "127.0.0.1", start_port: int = 10808) -> list[dict[str, Any]]:
        captured: list[dict[str, Any]] = []

        class CapturingRunner(SubprocessSingBoxRunner):
            def __init__(self, config: dict[str, Any], **kwargs: Any) -> None:
                super().__init__(config, **kwargs)
                captured.append({
                    "config": config,
                    "sing_box": self.sing_box,
                    "listen": self.listen,
                    "start_port": self.start_port,
                })

            async def __aenter__(self) -> SingBoxEndpoint:
                return SingBoxEndpoint(listen=listen, start_port=start_port)

            async def __aexit__(self, *args: Any) -> None:
                return None

        monkeypatch.setattr("socksbox.downloader.SubprocessSingBoxRunner", CapturingRunner)
        return captured

    return _install


class TestRunDownloadVerificationRunnerIntegration:
    @pytest.mark.asyncio
    async def test_uses_subprocess_runner_for_download_phase(
        self,
        proxy_factory: Any,
        monkeypatch: Any,
        patch_sing_box_version: None,
        make_capture_runner: Any,
    ) -> None:
        proxy = proxy_factory(
            label="test-proxy",
            latency_ms=10.0,
            outbound={"type": "socks", "server": "127.0.0.1", "server_port": 1080},
        )

        captured = make_capture_runner(listen="127.0.0.1", start_port=15000)

        async def fake_download(*args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "status": "ok",
                "url": "http://example.com/file",
                "bytes_downloaded": 1024,
                "elapsed_s": 1.0,
                "speed_kbps": 8.0,
                "http_status": 200,
            }

        monkeypatch.setattr("socksbox.downloader.download_through_proxy", fake_download)

        report = await run_download_verification(
            [proxy],
            start_port=15000,
            listen="127.0.0.1",
            sing_box="sing-box",
            url="http://example.com/file",
            timeout=5.0,
        )

        assert len(captured) == 1
        assert captured[0]["sing_box"] == "sing-box"
        assert captured[0]["listen"] == "127.0.0.1"
        assert captured[0]["start_port"] == 15000
        assert captured[0]["config"]["inbounds"][0]["listen"] == "127.0.0.1"
        assert captured[0]["config"]["inbounds"][0]["listen_port"] == 15000

        assert report["tested_proxies"] == 1
        assert report["passed"] == 1
        assert report["failed"] == 0
        assert report["success_rate"] == 1.0
        assert report["demoted"] == 0
        assert proxy.diagnostics["download_test"]["status"] == "ok"

    @pytest.mark.asyncio
    async def test_uses_runner_endpoint_for_ports(
        self,
        proxy_factory: Any,
        monkeypatch: Any,
        patch_sing_box_version: None,
        make_capture_runner: Any,
    ) -> None:
        proxy = proxy_factory(
            label="endpoint-proxy",
            latency_ms=10.0,
            outbound={"type": "socks", "server": "127.0.0.1", "server_port": 1080},
        )

        make_capture_runner(listen="192.168.1.1", start_port=25000)

        captured_calls: list[dict[str, Any]] = []

        async def fake_download(listen: str, socks_port: int, **kwargs: Any) -> dict[str, Any]:
            captured_calls.append({"listen": listen, "socks_port": socks_port})
            return {
                "status": "ok",
                "url": "http://example.com/file",
                "bytes_downloaded": 512,
                "elapsed_s": 1.0,
                "speed_kbps": 4.0,
                "http_status": 200,
            }

        monkeypatch.setattr("socksbox.downloader.download_through_proxy", fake_download)

        await run_download_verification(
            [proxy],
            start_port=15000,
            listen="127.0.0.1",
            sing_box="sing-box",
        )

        assert captured_calls == [{"listen": "192.168.1.1", "socks_port": 25000}]

    @pytest.mark.asyncio
    async def test_demotes_failed_downloads(
        self,
        proxy_factory: Any,
        monkeypatch: Any,
        patch_sing_box_version: None,
        make_capture_runner: Any,
    ) -> None:
        proxy = proxy_factory(
            label="failing-proxy",
            latency_ms=10.0,
            outbound={"type": "socks", "server": "127.0.0.1", "server_port": 1080},
        )

        make_capture_runner()

        async def fake_download(*args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "status": "failed",
                "url": "http://example.com/file",
                "bytes_downloaded": 0,
                "elapsed_s": 0.5,
                "speed_kbps": 0.0,
                "http_status": None,
                "error_type": "ConnectionError",
                "error": "could not connect",
            }

        monkeypatch.setattr("socksbox.downloader.download_through_proxy", fake_download)

        report = await run_download_verification(
            [proxy],
            start_port=10808,
            listen="127.0.0.1",
            sing_box="sing-box",
            demote_on_failure=True,
        )

        assert report["passed"] == 0
        assert report["failed"] == 1
        assert report["demoted"] == 1
        assert proxy.latency_ms == float("inf")
        assert proxy.diagnostics["download_test"]["error_type"] == "ConnectionError"

    @pytest.mark.asyncio
    async def test_does_not_demote_when_disabled(
        self,
        proxy_factory: Any,
        monkeypatch: Any,
        patch_sing_box_version: None,
        make_capture_runner: Any,
    ) -> None:
        proxy = proxy_factory(
            label="failing-proxy",
            latency_ms=10.0,
            outbound={"type": "socks", "server": "127.0.0.1", "server_port": 1080},
        )

        make_capture_runner()

        async def fake_download(*args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "status": "failed",
                "url": "http://example.com/file",
                "bytes_downloaded": 0,
                "elapsed_s": 0.5,
                "speed_kbps": 0.0,
                "http_status": None,
                "error_type": "ConnectionError",
                "error": "could not connect",
            }

        monkeypatch.setattr("socksbox.downloader.download_through_proxy", fake_download)

        report = await run_download_verification(
            [proxy],
            start_port=10808,
            listen="127.0.0.1",
            sing_box="sing-box",
            demote_on_failure=False,
        )

        assert report["demoted"] == 0
        assert proxy.latency_ms == 10.0

    @pytest.mark.asyncio
    async def test_returns_report_when_runner_dies_early(
        self,
        proxy_factory: Any,
        monkeypatch: Any,
        patch_sing_box_version: None,
    ) -> None:
        proxy = proxy_factory(
            label="test-proxy",
            latency_ms=10.0,
            outbound={"type": "socks", "server": "127.0.0.1", "server_port": 1080},
        )

        class FailingRunner(SubprocessSingBoxRunner):
            async def __aenter__(self) -> SingBoxEndpoint:
                raise RuntimeError("sing-box terminated early during startup")

            async def __aexit__(self, *args: Any) -> None:
                return None

        monkeypatch.setattr("socksbox.downloader.SubprocessSingBoxRunner", FailingRunner)

        report = await run_download_verification(
            [proxy],
            start_port=10808,
            listen="127.0.0.1",
            sing_box="sing-box",
        )

        assert report["tested_proxies"] == 1
        assert any(e["stage"] == "runner" for e in report["errors"])

    @pytest.mark.asyncio
    async def test_returns_early_when_no_working_proxies(
        self,
        proxy_factory: Any,
        tmp_path: Path,
    ) -> None:
        proxy = proxy_factory(
            label="not-working",
            latency_ms=float("inf"),
            outbound={"type": "socks", "server": "127.0.0.1", "server_port": 1080},
        )

        report = await run_download_verification(
            [proxy],
            start_port=10808,
            listen="127.0.0.1",
            sing_box="sing-box",
            output_dir=tmp_path,
        )

        assert report["total_proxies"] == 1
        assert report["tested_proxies"] == 0
        assert report["passed"] == 0
        assert (tmp_path / "download_report.json").exists()

    @pytest.mark.asyncio
    async def test_returns_early_when_port_range_exceeded(
        self,
        proxy_factory: Any,
        tmp_path: Path,
    ) -> None:
        proxies = [
            proxy_factory(
                label=f"proxy-{i}",
                latency_ms=10.0,
                outbound={"type": "socks", "server": "127.0.0.1", "server_port": 1080 + i},
            )
            for i in range(11)
        ]

        report = await run_download_verification(
            proxies,
            start_port=65530,
            listen="127.0.0.1",
            sing_box="sing-box",
            output_dir=tmp_path,
        )

        assert report["tested_proxies"] == 11
        assert any(e["stage"] == "setup" for e in report["errors"])
        assert (tmp_path / "download_report.json").exists()

    @pytest.mark.asyncio
    async def test_returns_early_when_sing_box_unavailable(
        self,
        proxy_factory: Any,
        monkeypatch: Any,
        tmp_path: Path,
    ) -> None:
        proxy = proxy_factory(
            label="test-proxy",
            latency_ms=10.0,
            outbound={"type": "socks", "server": "127.0.0.1", "server_port": 1080},
        )

        def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
            raise FileNotFoundError("sing-box not found")

        monkeypatch.setattr(subprocess, "run", fake_run)

        report = await run_download_verification(
            [proxy],
            start_port=10808,
            listen="127.0.0.1",
            sing_box="sing-box",
            output_dir=tmp_path,
        )

        assert report["tested_proxies"] == 1
        assert any(e["stage"] == "setup" for e in report["errors"])
        assert (tmp_path / "download_report.json").exists()

    @pytest.mark.asyncio
    async def test_writes_report_when_output_dir_given(
        self,
        proxy_factory: Any,
        monkeypatch: Any,
        patch_sing_box_version: None,
        make_capture_runner: Any,
        tmp_path: Path,
    ) -> None:
        proxy = proxy_factory(
            label="report-proxy",
            latency_ms=10.0,
            outbound={"type": "socks", "server": "127.0.0.1", "server_port": 1080},
        )

        make_capture_runner()

        async def fake_download(*args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "status": "ok",
                "url": "http://example.com/file",
                "bytes_downloaded": 1024,
                "elapsed_s": 1.0,
                "speed_kbps": 8.0,
                "http_status": 200,
            }

        monkeypatch.setattr("socksbox.downloader.download_through_proxy", fake_download)

        report = await run_download_verification(
            [proxy],
            start_port=10808,
            listen="127.0.0.1",
            sing_box="sing-box",
            output_dir=tmp_path,
        )

        report_path = tmp_path / "download_report.json"
        assert report_path.exists()
        written = report_path.read_text(encoding="utf-8")
        assert "report-proxy" in written
        assert report["passed"] == 1
