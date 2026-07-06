from __future__ import annotations

from urllib.parse import unquote, urlsplit
from socksbox.parsing.helpers import parse_port, fragment_label


class NaiveproxyParser:
    @property
    def schemes(self) -> tuple[str, ...]:
        return ("naive+https", "naive+quic")

    def parse(self, link: str) -> tuple[dict, str, str]:
        lower = link.lower()
        if lower.startswith("naive+quic://"):
            network = "quic"
            inner = "quic://" + link[len("naive+quic://"):]
        elif lower.startswith("naive+https://"):
            network = "https"
            inner = "https://" + link[len("naive+https://"):]
        else:
            raise ValueError(f"unsupported NaiveProxy scheme in: {link}")
        try:
            parsed = urlsplit(inner)
            server = parsed.hostname
            server_port = parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid NaiveProxy URL: {exc}") from exc
        if not server:
            raise ValueError("NaiveProxy link is missing its server")
        if server_port is None:
            server_port = 443
        outbound = {
            "type": "naiveproxy",
            "network": network,
            "server": server,
            "server_port": parse_port(server_port),
        }
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        if username:
            outbound["username"] = username
        if password:
            outbound["password"] = password
        label = fragment_label(link, "NaiveProxy")
        return outbound, label, "naiveproxy"
