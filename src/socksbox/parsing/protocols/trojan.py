from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlsplit
from socksbox.parsing.helpers import first, parse_port, build_tls, build_transport, fragment_label


class TrojanParser:
    @property
    def schemes(self) -> tuple[str, ...]:
        return ("trojan",)

    def parse(self, link: str) -> tuple[dict, str, str]:
        try:
            parsed = urlsplit(link)
            server = parsed.hostname
            server_port = parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid Trojan URL: {exc}") from exc
        if not server:
            raise ValueError("Trojan link is missing its server")
        if server_port is None:
            raise ValueError("Trojan link is missing its server port")
        password = unquote(parsed.username or "")
        if not password:
            raise ValueError("Trojan link is missing its password")
        query = parse_qs(parsed.query, keep_blank_values=True)
        outbound = {
            "type": "trojan",
            "server": server,
            "server_port": parse_port(server_port),
            "password": password,
        }
        security = first(query, "security", "tls")
        if security.lower() not in {"none", "0", "false"}:
            tls_config = build_tls(query, "tls")
            if tls_config:
                outbound["tls"] = tls_config
            else:
                outbound["tls"] = {"enabled": True}
        transport = build_transport(first(query, "type") or "tcp", query, first(query, "headerType", "header_type"))
        if transport:
            outbound["transport"] = transport
        label = fragment_label(link, "Trojan proxy")
        return outbound, label, "trojan"
