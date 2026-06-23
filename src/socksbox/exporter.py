from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from socksbox.models import ProxyInfo


def export_all(
    proxies: list[ProxyInfo],
    config: dict[str, Any],
    output_dir: Path,
    start_port: int = 10808,
    issues: list[dict[str, Any]] | None = None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    working = [p for p in proxies if p.working]
    failed = [p for p in proxies if not p.working]

    # all.txt
    with (output_dir / "all.txt").open("w", encoding="utf-8") as f:
        f.write(f"# All proxies: {len(proxies)} total, {len(working)} working, {len(failed)} failed\n")
        for p in proxies:
            status = f"{p.latency_ms:.1f}ms" if p.working else "FAILED"
            f.write(f"{p.link}  # {p.protocol} | {status} | {p.label}\n")

    # all_working.txt
    with (output_dir / "all_working.txt").open("w", encoding="utf-8") as f:
        f.write(f"# Working proxies sorted by latency: {len(working)} total\n")
        for p in working:
            f.write(f"{p.link}\n")

    # top10.txt
    with (output_dir / "top10.txt").open("w", encoding="utf-8") as f:
        f.write(f"# Top 10 fastest proxies\n")
        for rank, p in enumerate(working[:10], 1):
            geo = p.country_code or "?"
            f.write(f"# {rank:2d}. {p.latency_ms:6.1f}ms | {p.protocol:12s} | {geo} | {p.label}\n")
            f.write(f"{p.link}\n")

    # by_protocol/
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

    # by_country/
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

    # config.json
    with (output_dir / "config.json").open("w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
        f.write("\n")

    # summary.json
    country_counts = {cc: len(items) for cc, items in sorted(by_country.items())}
    protocol_counts = {proto: len(items) for proto, items in sorted(by_protocol.items())}
    summary = {
        "total": len(proxies),
        "working": len(working),
        "failed": len(failed),
        "countries": len(by_country),
        "protocols": len(by_protocol),
        "by_country": country_counts,
        "by_protocol": protocol_counts,
        "top10": [
            {"rank": i + 1, "latency_ms": round(p.latency_ms, 1), "protocol": p.protocol,
             "country": p.country_code, "label": p.label}
            for i, p in enumerate(working[:10])
        ],
    }
    with (output_dir / "summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
        f.write("\n")

    diagnostics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "issue_counts": _count_issue_categories(issues or []),
        "issues": issues or [],
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
            }
            for i, p in enumerate(proxies)
        ],
    }
    with (output_dir / "diagnostics.json").open("w", encoding="utf-8") as f:
        json.dump(diagnostics, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Exported to {output_dir}/:", file=sys.stderr)
    print(f"  all.txt           ({len(proxies)} proxies)", file=sys.stderr)
    print(f"  all_working.txt   ({len(working)} proxies)", file=sys.stderr)
    print(f"  top10.txt", file=sys.stderr)
    print(f"  by_protocol/      ({len(by_protocol)} protocols)", file=sys.stderr)
    print(f"  by_country/       ({len(by_country)} countries)", file=sys.stderr)
    print(f"  config.json", file=sys.stderr)
    print(f"  summary.json", file=sys.stderr)
    print(f"  diagnostics.json", file=sys.stderr)


def _count_issue_categories(issues: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for issue in issues:
        stage = str(issue.get("stage", "unknown"))
        kind = str(issue.get("kind") or issue.get("reason") or issue.get("error_type") or "unknown")
        counts[f"{stage}:{kind}"] += 1
    return dict(sorted(counts.items()))
