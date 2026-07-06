from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlsplit
from socksbox.parsing.helpers import first, parse_port, build_tls, build_transport, fragment_label


class VLessParser:
    @property
    def schemes(self) -> tuple[str, ...]:
        return ("vless",)

    def parse(self, link: str) -> tuple[dict, str, str]:
        try:
            parsed = urlsplit(link)
            server = parsed.hostname
            server_port = parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid VLESS URL: {exc}") from exc
        if not server:
            raise ValueError("VLESS link is missing its server")
        if server_port is None:
            raise ValueError("VLESS link is missing its server port")
        uuid = unquote(parsed.username or "")
        if not uuid:
            raise ValueError("VLESS link is missing its UUID")
        query = parse_qs(parsed.query, keep_blank_values=True)
        outbound = {
            "type": "vless",
            "server": server,
            "server_port": parse_port(server_port),
            "uuid": uuid,
        }
        flow = first(query, "flow")
        if flow:
            flow_str = str(flow)
            if flow_str == "xtls-rprx-vision":
                outbound["flow"] = flow_str
        tls = build_tls(query, first(query, "security"))
        if tls:
            outbound["tls"] = tls
        transport = build_transport(first(query, "type") or "tcp", query, first(query, "headerType", "header_type"))
        if transport:
            outbound["transport"] = transport
        packet_encoding = first(query, "packetEncoding", "packet_encoding")
        if packet_encoding:
            pe_str = str(packet_encoding).strip().lower()
            if pe_str in {"xudp", "packetaddr"}:
                outbound["packet_encoding"] = pe_str
        label = fragment_label(link, "VLESS proxy")
        return outbound, label, "vless"
