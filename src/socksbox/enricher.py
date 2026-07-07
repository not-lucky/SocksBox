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
    tokens: dict[str, str] | None = None,
    active_providers: list[str] | None = None,
) -> ProxyInfo:
    """Enrich a single proxy by delegating to the GeoEnricher decorator chain."""
    core = BaseEnricher()
    decorator = GeoEnricher(core)
    return await decorator.enrich(
        proxy,
        socks_port,
        listen=listen,
        token=token,
        timeout=timeout,
        audit_log_path=audit_log_path,
        tokens=tokens,
        active_providers=active_providers,
    )


async def enrich_proxies(
    proxies: list[ProxyInfo],
    start_port: int = 10808,
    listen: str = "127.0.0.1",
    concurrency: int = 50,
    tokens: list[str] | None = None,
    verbose: bool = False,
    audit_log_path: Path | None = None,
    provider_tokens: dict[str, list[str]] | None = None,
    active_providers: list[str] | None = None,
) -> list[ProxyInfo]:
    working = [p for p in proxies if p.working]
    if not working:
        print("No working proxies to enrich.", file=sys.stderr)
        return proxies

    # Handle backward compatibility
    if tokens and not provider_tokens:
        provider_tokens = {"ipinfo": tokens}
    elif not provider_tokens:
        provider_tokens = {}

    # Cycle tokens for each provider
    token_cycles = {
        name: itertools.cycle(toks) if toks else itertools.repeat("")
        for name, toks in provider_tokens.items()
    }

    if provider_tokens:
        print(f"Enriching {len(working)} working proxies with geo info (cycling provider API token(s))...", file=sys.stderr)
    else:
        print(f"Enriching {len(working)} working proxies with geo info...", file=sys.stderr)

    sem = asyncio.Semaphore(concurrency)
    completed = 0
    total = len(working)

    async def worker(proxy: ProxyInfo, port: int, current_tokens: dict[str, str]) -> ProxyInfo:
        nonlocal completed
        async with sem:
            ipinfo_tok = current_tokens.get("ipinfo", "")
            result = await enrich_proxy(
                proxy,
                port,
                listen=listen,
                token=ipinfo_tok,
                audit_log_path=audit_log_path,
                tokens=current_tokens,
                active_providers=active_providers,
            )
            completed += 1
            print(f"Enrich progress: {completed}/{total}...", end="\r", file=sys.stderr)
            if verbose and not result.country_code:
                print(f"\n  Geo lookup failed for port {port} ({proxy.label})", file=sys.stderr)
            return result

    index_map = {id(p): i for i, p in enumerate(proxies)}
    
    # Pre-generate token snapshot for each task
    tasks = []
    for p in working:
        port = start_port + index_map[id(p)]
        current_tokens = {
            name: next(cycle)
            for name, cycle in token_cycles.items()
        }
        tasks.append(worker(p, port, current_tokens))

    await asyncio.gather(*tasks)
    print("", file=sys.stderr)
    return proxies
