from __future__ import annotations

from urllib.parse import unquote, urlsplit
from socksbox.parsing.helpers import parse_port, fragment_label


class Socks5Parser:
    @property
    def schemes(self) -> tuple[str, ...]:
        return ("socks5",)

    def parse(self, link: str) -> tuple[dict, str, str]:
        try:
            parsed = urlsplit(link)
            server = parsed.hostname
            server_port = parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid SOCKS5 URL: {exc}") from exc
        if not server:
            raise ValueError("SOCKS5 link is missing its server")
        if server_port is None:
            server_port = 1080
        outbound = {
            "type": "socks",
            "server": server,
            "server_port": parse_port(server_port),
            "version": "5",
        }
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        if username:
            outbound["username"] = username
        if password:
            outbound["password"] = password
        label = fragment_label(link, "SOCKS5 proxy")
        return outbound, label, "socks5"
