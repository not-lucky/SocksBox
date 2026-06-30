from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from socksbox.exporters.base import BaseExporter
from socksbox.models import ProxyInfo


class GroupedExporter(BaseExporter):
    """Write proxies grouped by protocol and by country."""

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

        by_protocol_dir = output_dir / "by_protocol"
        by_protocol_dir.mkdir(exist_ok=True)
        by_protocol: dict[str, list[ProxyInfo]] = defaultdict(list)
        for p in working:
            by_protocol[p.protocol].append(p)
        for protocol, items in sorted(by_protocol.items()):
            with (by_protocol_dir / f"{protocol}.txt").open("w", encoding="utf-8") as f:
                f.write(f"# {protocol} proxies: {len(items)} working\n")
                for p in items:
                    f.write(f"{p.link}\n")

        by_country_dir = output_dir / "by_country"
        by_country_dir.mkdir(exist_ok=True)
        by_country: dict[str, list[ProxyInfo]] = defaultdict(list)
        for p in working:
            cc = p.country_code or "UNKNOWN"
            by_country[cc].append(p)
        for cc, items in sorted(by_country.items()):
            items.sort(key=lambda p: p.latency_ms)
            with (by_country_dir / f"{cc}.txt").open("w", encoding="utf-8") as f:
                f.write(f"# {cc} proxies: {len(items)} working\n")
                for p in items:
                    f.write(f"{p.link}\n")
