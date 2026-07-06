from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlsplit
from socksbox.parsing.helpers import first, parse_port, build_tls, fragment_label


class Hysteria2Parser:
    @property
    def schemes(self) -> tuple[str, ...]:
        return ("hysteria2", "hy2")

    def parse(self, link: str) -> tuple[dict, str, str]:
        try:
            parsed = urlsplit(link)
            server = parsed.hostname
            server_port = parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid Hysteria2 URL: {exc}") from exc
        if not server:
            raise ValueError("Hysteria2 link is missing its server")
        if server_port is None:
            server_port = 443
        userinfo = unquote(parsed.username or "")
        if not userinfo:
            raise ValueError("Hysteria2 link is missing its credentials")
        if ":" in userinfo:
            password = userinfo.split(":", 1)[1]
        else:
            password = userinfo
        query = parse_qs(parsed.query, keep_blank_values=True)
        outbound = {
            "type": "hysteria2",
            "server": server,
            "server_port": parse_port(server_port),
            "password": password,
        }
        tls_config = build_tls(query, "tls")
        if tls_config:
            outbound["tls"] = tls_config
        else:
            outbound["tls"] = {"enabled": True}
        obfs_type = first(query, "obfs")
        if obfs_type:
            obfs_pass = first(query, "obfs-password", "obfs_password")
            outbound["obfs"] = {"type": obfs_type}
            if obfs_pass:
                outbound["obfs"]["password"] = obfs_pass
        label = fragment_label(link, "Hysteria2 proxy")
        return outbound, label, "hysteria2"
