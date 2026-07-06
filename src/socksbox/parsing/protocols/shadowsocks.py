from __future__ import annotations

from urllib.parse import parse_qs, unquote
from socksbox.parsing.helpers import first, decode_base64_text, parse_endpoint, fragment_label


def decode_ss_credentials(userinfo: str) -> tuple[str, str]:
    candidate = unquote(userinfo)
    try:
        decoded = decode_base64_text(candidate)
        if ":" in decoded:
            parts = decoded.split(":", 1)
            return parts[0], parts[1]
    except ValueError:
        pass
    if ":" in candidate:
        parts = candidate.split(":", 1)
        return parts[0], parts[1]
    raise ValueError("invalid Shadowsocks credentials")


class ShadowsocksParser:
    @property
    def schemes(self) -> tuple[str, ...]:
        return ("ss",)

    def parse(self, link: str) -> tuple[dict, str, str]:
        without_fragment = link.split("#", 1)[0]
        body = without_fragment[len("ss://"):]
        if "?" in body:
            body, query_string = body.split("?", 1)
        else:
            query_string = ""
        if "@" in body:
            userinfo, address = body.rsplit("@", 1)
            method, password = decode_ss_credentials(userinfo)
        else:
            decoded = decode_base64_text(body)
            if "@" not in decoded:
                raise ValueError("legacy Shadowsocks link is missing server address")
            credentials, address = decoded.rsplit("@", 1)
            if ":" not in credentials:
                raise ValueError("invalid legacy Shadowsocks credentials")
            method, password = credentials.split(":", 1)
        server, server_port = parse_endpoint(address)
        outbound = {
            "type": "shadowsocks",
            "server": server,
            "server_port": server_port,
            "method": method,
            "password": password,
        }
        query = parse_qs(query_string, keep_blank_values=True)
        plugin = first(query, "plugin")
        if plugin:
            plugin_name, separator, plugin_options = str(plugin).partition(";")
            outbound["plugin"] = plugin_name
            if separator and plugin_options:
                outbound["plugin_opts"] = plugin_options
        label = fragment_label(link, "Shadowsocks proxy")
        return outbound, label, "shadowsocks"
