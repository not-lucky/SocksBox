from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlsplit
from socksbox.parsing.helpers import parse_port, build_tls, fragment_label


class TuicParser:
    @property
    def schemes(self) -> tuple[str, ...]:
        return ("tuic",)

    def parse(self, link: str) -> tuple[dict, str, str]:
        try:
            parsed = urlsplit(link)
            server = parsed.hostname
            server_port = parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid TUIC URL: {exc}") from exc
        if not server:
            raise ValueError("TUIC link is missing its server")
        if server_port is None:
            server_port = 443
        userinfo = unquote(parsed.username or "")
        if not userinfo:
            raise ValueError("TUIC link is missing credentials")
        if ":" in userinfo:
            uuid, password = userinfo.split(":", 1)
        else:
            uuid = userinfo
            password = ""
        query = parse_qs(parsed.query, keep_blank_values=True)
        outbound = {
            "type": "tuic",
            "server": server,
            "server_port": parse_port(server_port),
            "uuid": uuid,
        }
        if password:
            outbound["password"] = password
        tls_config = build_tls(query, "tls")
        if tls_config:
            outbound["tls"] = tls_config
        else:
            outbound["tls"] = {"enabled": True}
        label = fragment_label(link, "TUIC proxy")
        return outbound, label, "tuic"
