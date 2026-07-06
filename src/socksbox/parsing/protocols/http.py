from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlsplit
from socksbox.parsing.helpers import parse_port, build_tls, fragment_label


class HttpParser:
    @property
    def schemes(self) -> tuple[str, ...]:
        return ("http", "https")

    def parse(self, link: str) -> tuple[dict, str, str]:
        try:
            parsed = urlsplit(link)
            server = parsed.hostname
            server_port = parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid HTTP proxy URL: {exc}") from exc
        if not server:
            raise ValueError("HTTP proxy link is missing its server")
        is_https = parsed.scheme.lower() == "https"
        if server_port is None:
            server_port = 443 if is_https else 80
        query = parse_qs(parsed.query, keep_blank_values=True)
        outbound = {
            "type": "http",
            "server": server,
            "server_port": parse_port(server_port),
        }
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        if username:
            outbound["username"] = username
        if password:
            outbound["password"] = password
        if is_https:
            tls_config = build_tls(query, "tls")
            outbound["tls"] = tls_config if tls_config else {"enabled": True}
        label = fragment_label(link, "HTTP proxy")
        return outbound, label, "http"
