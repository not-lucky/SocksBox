from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from socksbox.exporters.base import BaseExporter
from socksbox.models import ProxyInfo


def _count_issue_categories(issues: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for issue in issues:
        stage = str(issue.get("stage", "unknown"))
        kind = str(
            issue.get("kind")
            or issue.get("reason")
            or issue.get("error_type")
            or "unknown"
        )
        counts[f"{stage}:{kind}"] += 1
    return dict(sorted(counts.items()))


class ConfigExporter(BaseExporter):
    """Write the sing-box configuration to config.json."""

    def write(
        self,
        proxies: list[ProxyInfo],
        config: dict[str, Any],
        output_dir: Path,
        start_port: int,
        issues: list[dict[str, Any]],
    ) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        with (output_dir / "config.json").open("w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
            f.write("\n")


class SummaryExporter(BaseExporter):
    """Write summary.json with aggregate counts and top 10 proxies."""

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

        by_protocol: dict[str, list[ProxyInfo]] = defaultdict(list)
        by_country: dict[str, list[ProxyInfo]] = defaultdict(list)
        for p in working:
            by_protocol[p.protocol].append(p)
            cc = p.country_code or "UNKNOWN"
            by_country[cc].append(p)

        country_counts = {cc: len(items) for cc, items in sorted(by_country.items())}
        protocol_counts = {
            proto: len(items) for proto, items in sorted(by_protocol.items())
        }

        summary = {
            "total": len(proxies),
            "working": len(working),
            "failed": len(failed),
            "countries": len(by_country),
            "protocols": len(by_protocol),
            "by_country": country_counts,
            "by_protocol": protocol_counts,
            "top10": [
                {
                    "rank": i + 1,
                    "latency_ms": round(p.latency_ms, 1),
                    "protocol": p.protocol,
                    "country": p.country_code,
                    "label": p.label,
                }
                for i, p in enumerate(working[:10])
            ],
        }

        with (output_dir / "summary.json").open("w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
            f.write("\n")


class DiagnosticsExporter(BaseExporter):
    """Write diagnostics.json with full proxy and issue details."""

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

        by_protocol: dict[str, list[ProxyInfo]] = defaultdict(list)
        by_country: dict[str, list[ProxyInfo]] = defaultdict(list)
        for p in working:
            by_protocol[p.protocol].append(p)
            cc = p.country_code or "UNKNOWN"
            by_country[cc].append(p)

        country_counts = {cc: len(items) for cc, items in sorted(by_country.items())}
        protocol_counts = {
            proto: len(items) for proto, items in sorted(by_protocol.items())
        }

        summary = {
            "total": len(proxies),
            "working": len(working),
            "failed": len(self.failed(proxies)),
            "countries": len(by_country),
            "protocols": len(by_protocol),
            "by_country": country_counts,
            "by_protocol": protocol_counts,
            "top10": [
                {
                    "rank": i + 1,
                    "latency_ms": round(p.latency_ms, 1),
                    "protocol": p.protocol,
                    "country": p.country_code,
                    "label": p.label,
                }
                for i, p in enumerate(working[:10])
            ],
        }

        diagnostics = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "issue_counts": _count_issue_categories(issues),
            "issues": issues,
            "proxies": [
                {
                    "index": i + 1,
                    "link": p.link,
                    "protocol": p.protocol,
                    "label": p.label,
                    "working": p.working,
                    "latency_ms": round(p.latency_ms, 1) if p.working else None,
                    "country_code": p.country_code,
                    "country": p.country,
                    "diagnostics": p.diagnostics,
                    "raw_geo": p.raw_geo,
                }
                for i, p in enumerate(proxies)
            ],
        }

        with (output_dir / "diagnostics.json").open("w", encoding="utf-8") as f:
            json.dump(diagnostics, f, indent=2, ensure_ascii=False)
            f.write("\n")
