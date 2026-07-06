from __future__ import annotations

import base64
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit


TRUE_VALUES = {"1", "true", "yes", "on"}


def first(mapping: dict, *keys: str) -> str | Any:
    for key in keys:
        if key not in mapping:
            continue
        value = mapping[key]
        if isinstance(value, list):
            if not value:
                continue
            value = value[0]
        if value is not None and value != "":
            return value
    return ""


def required(mapping: dict, description: str, *keys: str) -> str | Any:
    value = first(mapping, *keys)
    if value == "":
        raise ValueError(f"missing {description}")
    return value


def parse_bool(value: Any) -> bool:
    return str(value).strip().lower() in TRUE_VALUES


def parse_port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"invalid port: {value!r}")
    if not 1 <= port <= 65535:
        raise ValueError(f"port outside valid range: {port}")
    return port


def decode_base64_text(value: str) -> str:
    value = unquote(value).strip()
    value += "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
        return decoded.decode("utf-8")
    except Exception as exc:
        raise ValueError(f"invalid base64 data: {exc}") from exc


def fragment_label(link: str, fallback: str) -> str:
    if "#" not in link:
        return fallback
    label = unquote(link.split("#", 1)[1]).strip()
    return label or fallback


def parse_endpoint(address: str) -> tuple[str, int]:
    try:
        parsed = urlsplit("//" + address)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid server address {address!r}: {exc}") from exc
    if not host:
        raise ValueError(f"missing server hostname in {address!r}")
    if port is None:
        raise ValueError(f"missing server port in {address!r}")
    return host, parse_port(port)


def build_tls(values: dict, mode: str) -> dict | None:
    mode = str(mode or "").strip().lower()
    if mode in {"", "none", "0", "false"}:
        return None
    if mode not in {"tls", "reality"}:
        raise ValueError(f"unsupported TLS/security mode: {mode!r}")
    tls = {"enabled": True}
    server_name = first(values, "sni", "serverName", "server_name", "peer")
    if server_name:
        tls["server_name"] = str(server_name)
    insecure = first(values, "insecure", "allowInsecure", "allow_insecure")
    if insecure != "":
        tls["insecure"] = parse_bool(insecure)
    alpn = first(values, "alpn")
    if alpn:
        alpn_values = [item.strip() for item in str(alpn).split(",") if item.strip()]
        if alpn_values:
            tls["alpn"] = alpn_values
    fingerprint = first(values, "fp", "fingerprint")
    if fingerprint and str(fingerprint).lower() != "none":
        tls["utls"] = {"enabled": True, "fingerprint": str(fingerprint)}
    if mode == "reality":
        public_key = first(values, "pbk", "publicKey", "public_key")
        if not public_key:
            raise ValueError("Reality link is missing its public key")
        reality = {"enabled": True, "public_key": str(public_key)}
        short_id = first(values, "sid", "shortId", "short_id")
        if short_id:
            reality["short_id"] = str(short_id)
        tls["reality"] = reality
    return tls


def build_transport(kind: str, values: dict, header_type: str = "") -> dict | None:
    kind = str(kind or "tcp").strip().lower()
    header_type = str(header_type or "").strip().lower()
    if kind in {"", "tcp", "raw", "none"}:
        if header_type == "http":
            kind = "http"
        elif header_type not in {"", "none"}:
            raise ValueError(f"TCP header type {header_type!r} is not supported by this generator")
        else:
            return None
    host = str(first(values, "host") or "")
    path = str(first(values, "path") or "")
    if kind == "ws":
        transport = {"type": "ws"}
        if path:
            transport["path"] = path
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if kind in {"http", "h2"}:
        transport = {"type": "http"}
        if host:
            transport["host"] = [item.strip() for item in host.split(",") if item.strip()]
        if path:
            transport["path"] = path
        return transport
    if kind == "grpc":
        service_name = first(values, "serviceName", "service_name", "service", "path")
        transport = {"type": "grpc"}
        if service_name:
            transport["service_name"] = str(service_name).lstrip("/")
        return transport
    if kind in {"httpupgrade", "http-upgrade"}:
        transport = {"type": "httpupgrade"}
        if host:
            transport["host"] = host
        if path:
            transport["path"] = path
        return transport
    if kind == "quic":
        return {"type": "quic"}
    if kind in {"xhttp", "splithttp"}:
        raise ValueError(
            "Xray XHTTP/splitHTTP transport is not supported by sing-box; "
            "use a sing-box-compatible transport (tcp, http, ws, grpc, httpupgrade, or quic) "
            "or an Xray-based proxy client instead")
    raise ValueError(f"unsupported transport type: {kind!r}")
