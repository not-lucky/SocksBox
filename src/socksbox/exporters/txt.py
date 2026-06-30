from __future__ import annotations

from pathlib import Path
from typing import Any

from socksbox.exporters.base import BaseExporter
from socksbox.models import ProxyInfo


class AllTxtExporter(BaseExporter):
    """Write all.txt with every proxy and its status."""

    def write(
        self,
        proxies: list[ProxyInfo],
        config: dict[str, Any],
        output_dir: Path,
        start_port: int,
        issues: list[dict[str, Any]],
    ) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        working = self.working(proxies)
        failed = self.failed(proxies)

        with (output_dir / "all.txt").open("w", encoding="utf-8") as f:
            f.write(
                f"# All proxies: {len(proxies)} total, {len(working)} working, {len(failed)} failed\n"
            )
            for p in proxies:
                status = f"{p.latency_ms:.1f}ms" if p.working else "FAILED"
                f.write(f"{p.link}  # {p.protocol} | {status} | {p.label}\n")


class WorkingTxtExporter(BaseExporter):
    """Write all_working.txt with links for working proxies."""

    def write(
        self,
        proxies: list[ProxyInfo],
        config: dict[str, Any],
        output_dir: Path,
        start_port: int,
        issues: list[dict[str, Any]],
    ) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        working = self.working(proxies)

        with (output_dir / "all_working.txt").open("w", encoding="utf-8") as f:
            f.write(f"# Working proxies sorted by latency: {len(working)} total\n")
            for p in working:
                f.write(f"{p.link}\n")


class Top10TxtExporter(BaseExporter):
    """Write top10.txt with the ten fastest working proxies."""

    def write(
        self,
        proxies: list[ProxyInfo],
        config: dict[str, Any],
        output_dir: Path,
        start_port: int,
        issues: list[dict[str, Any]],
    ) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        working = self.working(proxies)

        with (output_dir / "top10.txt").open("w", encoding="utf-8") as f:
            f.write("# Top 10 fastest proxies\n")
            for rank, p in enumerate(working[:10], 1):
                geo = p.country_code or "?"
                f.write(
                    f"# {rank:2d}. {p.latency_ms:6.1f}ms | {p.protocol:12s} | {geo} | {p.label}\n"
                )
                f.write(f"{p.link}\n")
