from __future__ import annotations

from urllib.parse import parse_qs, urlsplit
from socksbox.parsing.helpers import first, required, parse_port, fragment_label


class WireguardParser:
    @property
    def schemes(self) -> tuple[str, ...]:
        return ("wg",)

    def parse(self, link: str) -> tuple[dict, str, str]:
        try:
            parsed = urlsplit(link)
            server = parsed.hostname
            server_port = parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid WireGuard URL: {exc}") from exc
        if not server:
            raise ValueError("WireGuard link is missing its endpoint")
        if server_port is None:
            server_port = 51820
        query = parse_qs(parsed.query, keep_blank_values=True)
        private_key = required(query, "WireGuard private key", "private_key")
        public_key = required(query, "WireGuard peer public key", "public_key")
        address = first(query, "address", "local_address")
        local_address = [item.strip() for item in str(address).split(",") if item.strip()] if address else []
        allowed_ips = first(query, "allowed_ips", "allowed-ips")
        pre_shared_key = first(query, "pre_shared_key", "preshared_key", "psk")
        peer = {"server": server, "server_port": parse_port(server_port), "public_key": str(public_key)}
        if pre_shared_key:
            peer["pre_shared_key"] = str(pre_shared_key)
        if allowed_ips:
            peer["allowed_ips"] = [item.strip() for item in str(allowed_ips).split(",") if item.strip()]
        outbound = {
            "type": "wireguard",
            "server": server,
            "server_port": parse_port(server_port),
            "local_address": local_address,
            "private_key": str(private_key),
            "peers": [peer],
        }
        label = fragment_label(link, "WireGuard tunnel")
        return outbound, label, "wireguard"
