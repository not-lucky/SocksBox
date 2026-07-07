from __future__ import annotations

from typing import Any

from socksbox.models import ProxyInfo


def generate_singbox_config(
    proxies: list[ProxyInfo],
    start_port: int = 10808,
    listen: str = "127.0.0.1",
    legacy_route: bool = False,
) -> dict[str, Any]:
    # Sort proxies: lower abuseConfidenceScore first; if tie, lower latency_ms first
    def get_sort_key(p: ProxyInfo) -> tuple[int, float]:
        score = 0
        if isinstance(p.raw_geo, dict) and "abuseipdb" in p.raw_geo:
            abuse_data = p.raw_geo["abuseipdb"]
            if isinstance(abuse_data, dict):
                val = abuse_data.get("data", {}).get("abuseConfidenceScore")
                if val is not None:
                    try:
                        score = int(val)
                    except (ValueError, TypeError):
                        pass
        return (score, p.latency_ms)

    sorted_proxies = sorted(proxies, key=get_sort_key)

    inbounds = []
    outbounds = []
    route_rules = []

    for index, proxy in enumerate(sorted_proxies):
        listen_port = start_port + index
        inbound_tag = f"socks-{index:03d}"
        outbound_tag = f"proxy-{index:03d}"

        inbounds.append({"type": "socks", "tag": inbound_tag, "listen": listen, "listen_port": listen_port})

        outbound = dict(proxy.outbound)
        outbound["tag"] = outbound_tag
        outbounds.append(outbound)

        if legacy_route:
            route_rules.append({"inbound": inbound_tag, "outbound": outbound_tag})
        else:
            route_rules.append({"inbound": inbound_tag, "action": "route", "outbound": outbound_tag})

    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": route_rules},
    }
