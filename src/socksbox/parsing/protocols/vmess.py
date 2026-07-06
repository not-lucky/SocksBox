from __future__ import annotations

import json
from socksbox.parsing.helpers import first, required, parse_port, decode_base64_text, build_tls, build_transport


class VMessParser:
    @property
    def schemes(self) -> tuple[str, ...]:
        return ("vmess",)

    def parse(self, link: str) -> tuple[dict, str, str]:
        payload = link[len("vmess://"):]
        decoded = decode_base64_text(payload)
        try:
            values = json.loads(decoded)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid VMess JSON: {exc}") from exc
        if not isinstance(values, dict):
            raise ValueError("VMess payload is not a JSON object")
        server = str(required(values, "VMess server", "add", "server"))
        server_port = parse_port(required(values, "VMess port", "port"))
        uuid = str(required(values, "VMess UUID", "id", "uuid"))
        outbound = {
            "type": "vmess",
            "server": server,
            "server_port": server_port,
            "uuid": uuid,
            "security": str(first(values, "scy") or "auto"),
        }
        alter_id = first(values, "aid", "alterId", "alter_id")
        if alter_id != "":
            try:
                outbound["alter_id"] = int(alter_id)
            except ValueError as exc:
                raise ValueError(f"invalid VMess alter ID: {alter_id!r}") from exc
        tls = build_tls(values, first(values, "tls"))
        if tls:
            outbound["tls"] = tls
        transport = build_transport(
            first(values, "net", "network") or "tcp", values, first(values, "type", "headerType")
        )
        if transport:
            outbound["transport"] = transport
        packet_encoding = first(values, "packetEncoding", "packet_encoding")
        if packet_encoding:
            pe_str = str(packet_encoding).strip().lower()
            if pe_str in {"xudp", "packetaddr"}:
                outbound["packet_encoding"] = pe_str
        label = str(first(values, "ps") or "VMess proxy")
        return outbound, label, "vmess"
