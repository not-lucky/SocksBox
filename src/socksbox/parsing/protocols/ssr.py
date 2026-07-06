from __future__ import annotations

from socksbox.parsing.helpers import parse_port, decode_base64_text, fragment_label


def decode_param(value: str) -> str:
    if not value:
        return ""
    try:
        return decode_base64_text(value.replace("-", "+").replace("_", "/"))
    except ValueError:
        return value


class SsrParser:
    @property
    def schemes(self) -> tuple[str, ...]:
        return ("ssr",)

    def parse(self, link: str) -> tuple[dict, str, str]:
        payload = link[len("ssr://"):]
        decoded = decode_base64_text(payload)
        main_part, separator, query_string = decoded.partition("/?")
        if not separator:
            main_part, separator, query_string = decoded.partition("?")
        parts = main_part.split(":")
        if len(parts) < 6:
            raise ValueError("SSR link has too few fields; expected server:port:protocol:method:obfs:password_b64")
        server = parts[0]
        server_port = parse_port(parts[1])
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        password_b64 = ":".join(parts[5:])
        try:
            password = decode_base64_text(password_b64)
        except ValueError as exc:
            raise ValueError(f"invalid SSR password: {exc}") from exc
        params = {}
        if query_string:
            for pair in query_string.split("&"):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    params[key] = value

        obfs_param = decode_param(params.get("obfsparam", ""))
        proto_param = decode_param(params.get("protoparam", ""))
        remarks = decode_param(params.get("remarks", ""))
        outbound = {
            "type": "shadowsocksr",
            "server": server,
            "server_port": server_port,
            "method": method,
            "password": password,
            "protocol": protocol,
            "obfs": obfs,
        }
        if obfs_param:
            outbound["obfs_param"] = obfs_param
        if proto_param:
            outbound["protocol_param"] = proto_param
        label = remarks or fragment_label(link, "ShadowsocksR proxy")
        return outbound, label, "shadowsocksr"
