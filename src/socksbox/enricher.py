from __future__ import annotations

import asyncio
import itertools
import json
import sys
from pathlib import Path

import aiohttp
from aiohttp_socks import SocksConnector

from socksbox.models import ProxyInfo
from socksbox.status import (
    IPINFO_FORBIDDEN_MARKER,
    IPINFO_FORBIDDEN_MARKER_PATH,
    IPINFO_FORBIDDEN_STATUS,
    _mark_proxy_not_working,
    _response_carries_forbidden,
    log_forbidden_detection,
)


async def enrich_proxy(
    proxy: ProxyInfo,
    socks_port: int,
    listen: str = "127.0.0.1",
    token: str = "",
    timeout: float = 10.0,
    audit_log_path: Path | None = None,
) -> ProxyInfo:
    url = "https://ipinfo.io/json"
    if token:
        url += f"?token={token}"
    enrich_diag = proxy.diagnostics.setdefault("enrich", {})
    enrich_diag.update({"status": "started", "socks_port": socks_port, "listen": listen, "url": url})
    try:
        connector = SocksConnector.from_url(f"socks5://{listen}:{socks_port}")
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                enrich_diag["http_status"] = resp.status
                body_text = await resp.text()
                if (
                    resp.status == IPINFO_FORBIDDEN_STATUS
                    and _response_carries_forbidden(body_text)
                ):
                    _mark_proxy_not_working(
                        proxy,
                        reason="ipinfo.io forbidden 403 response",
                        extra={
                            "http_status": resp.status,
                            "socks_port": socks_port,
                            "check_command": (
                                f"curl --socks5 {listen}:{socks_port} ipinfo.io/json"
                            ),
                        },
                    )
                    log_forbidden_detection(
                        proxy,
                        socks_port=socks_port,
                        audit_log_path=audit_log_path,
                        http_status=resp.status,
                    )
                    enrich_diag.update({"status": "failed", "reason": "ipinfo_forbidden_403"})
                    return proxy
                if resp.status != 200:
                    enrich_diag.update({"status": "failed", "reason": "non_200_response"})
                    return proxy
                try:
                    data = json.loads(body_text) if body_text else None
                except json.JSONDecodeError:
                    enrich_diag.update({"status": "failed", "reason": "invalid_json_payload"})
                    return proxy
                if not isinstance(data, dict):
                    enrich_diag.update({"status": "failed", "reason": "invalid_json_payload"})
                    return proxy
                proxy.raw_geo = data
                proxy.ip = str(data.get("ip", ""))
                proxy.country_code = str(data.get("country", ""))
                proxy.city = str(data.get("city", ""))
                proxy.region = str(data.get("region", ""))
                proxy.org = str(data.get("org", ""))
                proxy.timezone = str(data.get("timezone", ""))
                proxy.country = proxy.country_code
                enrich_diag.update(
                    {
                        "status": "ok",
                        "ip": proxy.ip,
                        "country_code": proxy.country_code,
                        "city": proxy.city,
                        "region": proxy.region,
                        "org": proxy.org,
                        "timezone": proxy.timezone,
                    }
                )
    except Exception as exc:
        enrich_diag.update(
            {
                "status": "failed",
                "reason": "exception",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        )
    return proxy


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
