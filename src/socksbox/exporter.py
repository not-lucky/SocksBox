from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from socksbox.exporters import DEFAULT_EXPORTERS
from socksbox.models import ProxyInfo


def export_all(
    proxies: list[ProxyInfo],
    config: dict[str, Any],
    output_dir: Path,
    start_port: int = 10808,
    issues: list[dict[str, Any]] | None = None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    # Composite Pattern: delegate writing to the composite exporter (fallback to list iteration for injected mocks)
    if hasattr(DEFAULT_EXPORTERS, "write"):
        DEFAULT_EXPORTERS.write(proxies, config, output_dir, start_port, issues or [])
    else:
        for exporter in DEFAULT_EXPORTERS:
            exporter.write(proxies, config, output_dir, start_port, issues or [])

    working = [p for p in proxies if p.working]

    by_protocol: dict[str, list[ProxyInfo]] = defaultdict(list)
    by_country: dict[str, list[ProxyInfo]] = defaultdict(list)
    for p in working:
        by_protocol[p.protocol].append(p)
        cc = p.country_code or "UNKNOWN"
        by_country[cc].append(p)

    print(f"Exported to {output_dir}/:", file=sys.stderr)
    print(f"  all.txt           ({len(proxies)} proxies)", file=sys.stderr)
    print(f"  all_working.txt   ({len(working)} proxies)", file=sys.stderr)
    print("  top10.txt", file=sys.stderr)
    print(f"  by_protocol/      ({len(by_protocol)} protocols)", file=sys.stderr)
    print(f"  by_country/       ({len(by_country)} countries)", file=sys.stderr)
    print("  config.json", file=sys.stderr)
    print("  summary.json", file=sys.stderr)
    print("  diagnostics.json", file=sys.stderr)
