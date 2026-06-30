"""Tests for the exporter adapter registry and individual exporters."""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from socksbox.exporter import export_all
from socksbox.exporters import (
    DEFAULT_EXPORTERS,
    AllTxtExporter,
    ConfigExporter,
    DiagnosticsExporter,
    GroupedExporter,
    SummaryExporter,
    Top10TxtExporter,
    WorkingTxtExporter,
)
from socksbox.models import ProxyInfo


EXPECTED_EXPORTER_CLASSES: list[type] = [
    AllTxtExporter,
    WorkingTxtExporter,
    Top10TxtExporter,
    GroupedExporter,
    ConfigExporter,
    SummaryExporter,
    DiagnosticsExporter,
]


@pytest.fixture
def sample_proxies(proxy_factory: Callable[..., ProxyInfo]) -> list[ProxyInfo]:
    """Return a mixed list of working and failed proxies across protocols/countries."""
    return [
        proxy_factory(
            link="socks5://us1.example.com:1080",
            protocol="socks5",
            label="us-socks-1",
            latency_ms=10.0,
            country_code="US",
            country="United States",
        ),
        proxy_factory(
            link="ss://gb1.example.com:8388",
            protocol="ss",
            label="gb-ss-1",
            latency_ms=25.0,
            country_code="GB",
            country="United Kingdom",
        ),
        proxy_factory(
            link="vmess://us2.example.com:443",
            protocol="vmess",
            label="us-vmess-1",
            latency_ms=15.0,
            country_code="US",
            country="United States",
        ),
        proxy_factory(
            link="trojan://dead.example.com:443",
            protocol="trojan",
            label="dead-trojan",
            latency_ms=float("inf"),
            country_code="DE",
            country="Germany",
        ),
        proxy_factory(
            link="vless://nl1.example.com:443",
            protocol="vless",
            label="nl-vless-1",
            latency_ms=5.0,
            country_code="NL",
            country="Netherlands",
        ),
        proxy_factory(
            link="ss://xx1.example.com:8388",
            protocol="ss",
            label="xx-ss-no-country",
            latency_ms=35.0,
        ),
    ]


@pytest.fixture
def many_proxies(proxy_factory: Callable[..., ProxyInfo]) -> list[ProxyInfo]:
    """Return 12 working proxies to exercise top-10 truncation."""
    return [
        proxy_factory(
            link=f"socks5://host{i}.example.com:1080",
            protocol="socks5",
            label=f"proxy-{i}",
            latency_ms=float(i * 10),
            country_code="US",
        )
        for i in range(1, 13)
    ]


@pytest.fixture
def sample_config() -> dict[str, Any]:
    return {"log": {"level": "info"}, "inbounds": [], "outbounds": []}


@pytest.fixture
def sample_issues() -> list[dict[str, Any]]:
    return [
        {"stage": "verify", "kind": "timeout"},
        {"stage": "verify", "kind": "timeout"},
        {"stage": "geo", "reason": "rate_limited"},
    ]


class TestDefaultRegistry:
    def test_default_exporters_count_and_order(self) -> None:
        assert len(DEFAULT_EXPORTERS) == len(EXPECTED_EXPORTER_CLASSES)
        assert [type(e) for e in DEFAULT_EXPORTERS] == EXPECTED_EXPORTER_CLASSES

    @pytest.mark.parametrize("cls", EXPECTED_EXPORTER_CLASSES)
    def test_each_exporter_class_is_instantiable(self, cls: type) -> None:
        instance = cls()
        assert instance is not None


class TestAllTxtExporter:
    def test_writes_header_and_status_lines(self, sample_proxies: list[ProxyInfo], tmp_path: Path) -> None:
        exporter = AllTxtExporter()
        exporter.write(sample_proxies, {}, tmp_path, 10808, [])

        content = (tmp_path / "all.txt").read_text(encoding="utf-8")
        assert "# All proxies: 6 total, 5 working, 1 failed" in content
        assert "socks5://us1.example.com:1080  # socks5 | 10.0ms | us-socks-1" in content
        assert "trojan://dead.example.com:443  # trojan | FAILED | dead-trojan" in content

    def test_creates_output_directory(self, sample_proxies: list[ProxyInfo], tmp_path: Path) -> None:
        exporter = AllTxtExporter()
        nested = tmp_path / "nested" / "out"
        exporter.write(sample_proxies, {}, nested, 10808, [])
        assert (nested / "all.txt").exists()


class TestWorkingTxtExporter:
    def test_writes_only_working_in_input_order(self, sample_proxies: list[ProxyInfo], tmp_path: Path) -> None:
        exporter = WorkingTxtExporter()
        exporter.write(sample_proxies, {}, tmp_path, 10808, [])

        content = (tmp_path / "all_working.txt").read_text(encoding="utf-8")
        assert "# Working proxies sorted by latency: 5 total" in content
        lines = [line for line in content.splitlines() if not line.startswith("#")]
        assert lines == [
            "socks5://us1.example.com:1080",
            "ss://gb1.example.com:8388",
            "vmess://us2.example.com:443",
            "vless://nl1.example.com:443",
            "ss://xx1.example.com:8388",
        ]

    def test_excludes_failed_proxies(self, sample_proxies: list[ProxyInfo], tmp_path: Path) -> None:
        exporter = WorkingTxtExporter()
        exporter.write(sample_proxies, {}, tmp_path, 10808, [])
        content = (tmp_path / "all_working.txt").read_text(encoding="utf-8")
        assert "dead.example.com" not in content


class TestTop10TxtExporter:
    def test_writes_ranking_comments(self, many_proxies: list[ProxyInfo], tmp_path: Path) -> None:
        exporter = Top10TxtExporter()
        exporter.write(many_proxies, {}, tmp_path, 10808, [])

        content = (tmp_path / "top10.txt").read_text(encoding="utf-8")
        assert "# Top 10 fastest proxies" in content
        assert "#  1." in content
        assert "# 10." in content
        assert "proxy-1" in content
        assert "proxy-10" in content
        assert "proxy-11" not in content
        assert "proxy-12" not in content

    def test_country_fallback_to_unknown(self, proxy_factory: Callable[..., ProxyInfo], tmp_path: Path) -> None:
        proxies = [
            proxy_factory(
                link="ss://host.example.com:8388",
                protocol="ss",
                label="no-country",
                latency_ms=12.0,
                country_code="",
            )
        ]
        exporter = Top10TxtExporter()
        exporter.write(proxies, {}, tmp_path, 10808, [])

        content = (tmp_path / "top10.txt").read_text(encoding="utf-8")
        assert "?" in content
        assert "no-country" in content


class TestGroupedExporter:
    def test_creates_by_protocol_files(self, sample_proxies: list[ProxyInfo], tmp_path: Path) -> None:
        exporter = GroupedExporter()
        exporter.write(sample_proxies, {}, tmp_path, 10808, [])

        by_protocol_dir = tmp_path / "by_protocol"
        assert by_protocol_dir.is_dir()
        assert (by_protocol_dir / "socks5.txt").exists()
        assert (by_protocol_dir / "ss.txt").exists()
        assert (by_protocol_dir / "vmess.txt").exists()
        assert (by_protocol_dir / "vless.txt").exists()
        assert not (by_protocol_dir / "trojan.txt").exists()

        socks5_content = (by_protocol_dir / "socks5.txt").read_text(encoding="utf-8")
        assert "# socks5 proxies: 1 working" in socks5_content
        assert "socks5://us1.example.com:1080" in socks5_content

    def test_creates_by_country_files_sorted_by_latency(self, sample_proxies: list[ProxyInfo], tmp_path: Path) -> None:
        exporter = GroupedExporter()
        exporter.write(sample_proxies, {}, tmp_path, 10808, [])

        by_country_dir = tmp_path / "by_country"
        assert by_country_dir.is_dir()
        assert (by_country_dir / "US.txt").exists()
        assert (by_country_dir / "GB.txt").exists()
        assert (by_country_dir / "NL.txt").exists()
        assert (by_country_dir / "UNKNOWN.txt").exists()
        assert not (by_country_dir / "DE.txt").exists()

        us_content = (by_country_dir / "US.txt").read_text(encoding="utf-8")
        assert "# US proxies: 2 working" in us_content
        us_lines = [line for line in us_content.splitlines() if not line.startswith("#")]
        assert us_lines == [
            "socks5://us1.example.com:1080",
            "vmess://us2.example.com:443",
        ]


class TestConfigExporter:
    def test_writes_config_json(self, sample_config: dict[str, Any], tmp_path: Path) -> None:
        exporter = ConfigExporter()
        exporter.write([], sample_config, tmp_path, 10808, [])

        written = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
        assert written == sample_config


class TestSummaryExporter:
    def test_summary_has_expected_fields(
        self,
        sample_proxies: list[ProxyInfo],
        sample_config: dict[str, Any],
        tmp_path: Path,
    ) -> None:
        exporter = SummaryExporter()
        exporter.write(sample_proxies, sample_config, tmp_path, 10808, [])

        summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
        assert summary["total"] == 6
        assert summary["working"] == 5
        assert summary["failed"] == 1
        assert summary["countries"] == 4
        assert summary["protocols"] == 4
        assert summary["by_country"] == {"GB": 1, "NL": 1, "UNKNOWN": 1, "US": 2}
        assert summary["by_protocol"] == {"socks5": 1, "ss": 2, "vless": 1, "vmess": 1}
        assert len(summary["top10"]) == 5
        assert summary["top10"][0] == {
            "rank": 1,
            "latency_ms": 10.0,
            "protocol": "socks5",
            "country": "US",
            "label": "us-socks-1",
        }


class TestDiagnosticsExporter:
    def test_diagnostics_has_expected_fields(
        self,
        sample_proxies: list[ProxyInfo],
        sample_config: dict[str, Any],
        sample_issues: list[dict[str, Any]],
        tmp_path: Path,
    ) -> None:
        exporter = DiagnosticsExporter()
        exporter.write(sample_proxies, sample_config, tmp_path, 10808, sample_issues)

        diagnostics = json.loads((tmp_path / "diagnostics.json").read_text(encoding="utf-8"))
        assert diagnostics["generated_at"].endswith("+00:00")
        assert diagnostics["issue_counts"] == {
            "geo:rate_limited": 1,
            "verify:timeout": 2,
        }
        assert diagnostics["issues"] == sample_issues
        assert diagnostics["summary"]["total"] == 6
        assert len(diagnostics["proxies"]) == 6
        first = diagnostics["proxies"][0]
        assert first["index"] == 1
        assert first["link"] == "socks5://us1.example.com:1080"
        assert first["working"] is True
        assert first["latency_ms"] == 10.0

    def test_failed_proxy_has_null_latency(
        self,
        sample_proxies: list[ProxyInfo],
        tmp_path: Path,
    ) -> None:
        exporter = DiagnosticsExporter()
        exporter.write(sample_proxies, {}, tmp_path, 10808, [])

        diagnostics = json.loads((tmp_path / "diagnostics.json").read_text(encoding="utf-8"))
        failed = next(p for p in diagnostics["proxies"] if not p["working"])
        assert failed["latency_ms"] is None


class TestExportAll:
    def test_creates_all_expected_files(
        self,
        sample_proxies: list[ProxyInfo],
        sample_config: dict[str, Any],
        sample_issues: list[dict[str, Any]],
        tmp_path: Path,
    ) -> None:
        export_all(sample_proxies, sample_config, tmp_path, 10808, sample_issues)

        assert (tmp_path / "all.txt").exists()
        assert (tmp_path / "all_working.txt").exists()
        assert (tmp_path / "top10.txt").exists()
        assert (tmp_path / "by_protocol").is_dir()
        assert (tmp_path / "by_country").is_dir()
        assert (tmp_path / "config.json").exists()
        assert (tmp_path / "summary.json").exists()
        assert (tmp_path / "diagnostics.json").exists()

    def test_fake_exporter_can_be_injected(
        self,
        sample_proxies: list[ProxyInfo],
        sample_config: dict[str, Any],
        sample_issues: list[dict[str, Any]],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls: list[tuple[Any, ...]] = []

        class FakeExporter:
            def write(
                self,
                proxies: list[ProxyInfo],
                config: dict[str, Any],
                output_dir: Path,
                start_port: int,
                issues: list[dict[str, Any]],
            ) -> None:
                calls.append((proxies, config, output_dir, start_port, issues))

        import socksbox.exporter

        original = socksbox.exporter.DEFAULT_EXPORTERS
        monkeypatch.setattr(
            socksbox.exporter,
            "DEFAULT_EXPORTERS",
            list(original) + [FakeExporter()],
        )

        export_all(sample_proxies, sample_config, tmp_path, 10808, sample_issues)

        assert len(calls) == 1
        assert calls[0][0] == sample_proxies
        assert calls[0][1] == sample_config
        assert calls[0][2] == tmp_path
        assert calls[0][3] == 10808
        assert calls[0][4] == sample_issues
