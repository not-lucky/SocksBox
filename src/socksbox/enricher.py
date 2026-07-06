from __future__ import annotations

import asyncio
import itertools
import sys
from pathlib import Path

from socksbox.models import ProxyInfo
from socksbox.enrichment import BaseEnricher, GeoEnricher


async def enrich_proxy(
    proxy: ProxyInfo,
    socks_port: int,
    listen: str = "127.0.0.1",
    token: str = "",
    timeout: float = 10.0,
    audit_log_path: Path | None = None,
) -> ProxyInfo:
    """Enrich a single proxy by delegating to the GeoEnricher decorator chain."""
    core = BaseEnricher()
    decorator = GeoEnricher(core)
    return await decorator.enrich(
        proxy, socks_port, listen=listen, token=token, timeout=timeout, audit_log_path=audit_log_path
    )


async def enrich_proxies(
    proxies: list[ProxyInfo],
    start_port: int = 10808,
    listen: str = "127.0.0.1",
    concurrency: int = 50,
    tokens: list[str] | None = None,
    verbose: bool = False,
    audit_log_path: Path | None = None,
) -> list[ProxyInfo]:
    working = [p for p in proxies if p.working]
    if not working:
        print("No working proxies to enrich.", file=sys.stderr)
        return proxies

    if tokens:
        print(f"Enriching {len(working)} working proxies with geo info (cycling {len(tokens)} API token(s))...", file=sys.stderr)
    else:
        print(f"Enriching {len(working)} working proxies with geo info...", file=sys.stderr)

    token_cycle = itertools.cycle(tokens) if tokens else itertools.repeat("")

    sem = asyncio.Semaphore(concurrency)
    completed = 0
    total = len(working)

    async def worker(proxy: ProxyInfo, port: int, token: str) -> ProxyInfo:
        nonlocal completed
        async with sem:
            result = await enrich_proxy(
                proxy, port, listen=listen, token=token, audit_log_path=audit_log_path
            )
            completed += 1
            print(f"Enrich progress: {completed}/{total}...", end="\r", file=sys.stderr)
            if verbose and not result.country_code:
                print(f"\n  Geo lookup failed for port {port} ({proxy.label})", file=sys.stderr)
            return result

    index_map = {id(p): i for i, p in enumerate(proxies)}
    tasks = [worker(p, start_port + index_map[id(p)], next(token_cycle)) for p in working]
    await asyncio.gather(*tasks)
    print("", file=sys.stderr)
    return proxies
