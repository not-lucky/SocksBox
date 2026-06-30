from __future__ import annotations

import base64
import json
import ssl
import sys
import urllib.request
from collections.abc import Callable
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from socksbox.models import ProxyInfo

TRUE_VALUES = {"1", "true", "yes", "on"}


def _first(mapping, *keys):
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


def _required(mapping, description, *keys):
    value = _first(mapping, *keys)
    if value == "":
        raise ValueError(f"missing {description}")
    return value


def _parse_bool(value):
    return str(value).strip().lower() in TRUE_VALUES


def _parse_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"invalid port: {value!r}")
    if not 1 <= port <= 65535:
        raise ValueError(f"port outside valid range: {port}")
    return port


def _decode_base64_text(value):
    value = unquote(value).strip()
    value += "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
        return decoded.decode("utf-8")
    except Exception as exc:
        raise ValueError(f"invalid base64 data: {exc}") from exc


def _fragment_label(link, fallback):
    if "#" not in link:
        return fallback
    label = unquote(link.split("#", 1)[1]).strip()
    return label or fallback


def _parse_endpoint(address):
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
    return host, _parse_port(port)


def _build_tls(values, mode):
    mode = str(mode or "").strip().lower()
    if mode in {"", "none", "0", "false"}:
        return None
    if mode not in {"tls", "reality"}:
        raise ValueError(f"unsupported TLS/security mode: {mode!r}")
    tls = {"enabled": True}
    server_name = _first(values, "sni", "serverName", "server_name", "peer")
    if server_name:
        tls["server_name"] = str(server_name)
    insecure = _first(values, "insecure", "allowInsecure", "allow_insecure")
    if insecure != "":
        tls["insecure"] = _parse_bool(insecure)
    alpn = _first(values, "alpn")
    if alpn:
        alpn_values = [item.strip() for item in str(alpn).split(",") if item.strip()]
        if alpn_values:
            tls["alpn"] = alpn_values
    fingerprint = _first(values, "fp", "fingerprint")
    if fingerprint and str(fingerprint).lower() != "none":
        tls["utls"] = {"enabled": True, "fingerprint": str(fingerprint)}
    if mode == "reality":
        public_key = _first(values, "pbk", "publicKey", "public_key")
        if not public_key:
            raise ValueError("Reality link is missing its public key")
        reality = {"enabled": True, "public_key": str(public_key)}
        short_id = _first(values, "sid", "shortId", "short_id")
        if short_id:
            reality["short_id"] = str(short_id)
        tls["reality"] = reality
    return tls


def _build_transport(kind, values, header_type=""):
    kind = str(kind or "tcp").strip().lower()
    header_type = str(header_type or "").strip().lower()
    if kind in {"", "tcp", "raw", "none"}:
        if header_type == "http":
            kind = "http"
        elif header_type not in {"", "none"}:
            raise ValueError(f"TCP header type {header_type!r} is not supported by this generator")
        else:
            return None
    host = str(_first(values, "host") or "")
    path = str(_first(values, "path") or "")
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
        service_name = _first(values, "serviceName", "service_name", "service", "path")
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


def _parse_vmess(link):
    payload = link[len("vmess://"):]
    decoded = _decode_base64_text(payload)
    try:
        values = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid VMess JSON: {exc}") from exc
    if not isinstance(values, dict):
        raise ValueError("VMess payload is not a JSON object")
    server = str(_required(values, "VMess server", "add", "server"))
    server_port = _parse_port(_required(values, "VMess port", "port"))
    uuid = str(_required(values, "VMess UUID", "id", "uuid"))
    outbound = {
        "type": "vmess",
        "server": server,
        "server_port": server_port,
        "uuid": uuid,
        "security": str(_first(values, "scy") or "auto"),
    }
    alter_id = _first(values, "aid", "alterId", "alter_id")
    if alter_id != "":
        try:
            outbound["alter_id"] = int(alter_id)
        except ValueError as exc:
            raise ValueError(f"invalid VMess alter ID: {alter_id!r}") from exc
    tls = _build_tls(values, _first(values, "tls"))
    if tls:
        outbound["tls"] = tls
    transport = _build_transport(
        _first(values, "net", "network") or "tcp", values, _first(values, "type", "headerType")
    )
    if transport:
        outbound["transport"] = transport
    packet_encoding = _first(values, "packetEncoding", "packet_encoding")
    if packet_encoding:
        pe_str = str(packet_encoding).strip().lower()
        if pe_str in {"xudp", "packetaddr"}:
            outbound["packet_encoding"] = pe_str
    label = str(_first(values, "ps") or "VMess proxy")
    return outbound, label, "vmess"


def _parse_vless(link):
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
        "server_port": _parse_port(server_port),
        "uuid": uuid,
    }
    flow = _first(query, "flow")
    if flow:
        flow_str = str(flow)
        if flow_str == "xtls-rprx-vision":
            outbound["flow"] = flow_str
    tls = _build_tls(query, _first(query, "security"))
    if tls:
        outbound["tls"] = tls
    transport = _build_transport(_first(query, "type") or "tcp", query, _first(query, "headerType", "header_type"))
    if transport:
        outbound["transport"] = transport
    packet_encoding = _first(query, "packetEncoding", "packet_encoding")
    if packet_encoding:
        pe_str = str(packet_encoding).strip().lower()
        if pe_str in {"xudp", "packetaddr"}:
            outbound["packet_encoding"] = pe_str
    label = _fragment_label(link, "VLESS proxy")
    return outbound, label, "vless"


def _decode_ss_credentials(userinfo):
    candidate = unquote(userinfo)
    try:
        decoded = _decode_base64_text(candidate)
        if ":" in decoded:
            return decoded.split(":", 1)
    except ValueError:
        pass
    if ":" in candidate:
        return candidate.split(":", 1)
    raise ValueError("invalid Shadowsocks credentials")


def _parse_ss(link):
    without_fragment = link.split("#", 1)[0]
    body = without_fragment[len("ss://"):]
    if "?" in body:
        body, query_string = body.split("?", 1)
    else:
        query_string = ""
    if "@" in body:
        userinfo, address = body.rsplit("@", 1)
        method, password = _decode_ss_credentials(userinfo)
    else:
        decoded = _decode_base64_text(body)
        if "@" not in decoded:
            raise ValueError("legacy Shadowsocks link is missing server address")
        credentials, address = decoded.rsplit("@", 1)
        if ":" not in credentials:
            raise ValueError("invalid legacy Shadowsocks credentials")
        method, password = credentials.split(":", 1)
    server, server_port = _parse_endpoint(address)
    outbound = {
        "type": "shadowsocks",
        "server": server,
        "server_port": server_port,
        "method": method,
        "password": password,
    }
    query = parse_qs(query_string, keep_blank_values=True)
    plugin = _first(query, "plugin")
    if plugin:
        plugin_name, separator, plugin_options = str(plugin).partition(";")
        outbound["plugin"] = plugin_name
        if separator and plugin_options:
            outbound["plugin_opts"] = plugin_options
    label = _fragment_label(link, "Shadowsocks proxy")
    return outbound, label, "shadowsocks"


def _parse_trojan(link):
    try:
        parsed = urlsplit(link)
        server = parsed.hostname
        server_port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid Trojan URL: {exc}") from exc
    if not server:
        raise ValueError("Trojan link is missing its server")
    if server_port is None:
        raise ValueError("Trojan link is missing its server port")
    password = unquote(parsed.username or "")
    if not password:
        raise ValueError("Trojan link is missing its password")
    query = parse_qs(parsed.query, keep_blank_values=True)
    outbound = {
        "type": "trojan",
        "server": server,
        "server_port": _parse_port(server_port),
        "password": password,
    }
    security = _first(query, "security", "tls")
    if security.lower() not in {"none", "0", "false"}:
        tls_config = _build_tls(query, "tls")
        if tls_config:
            outbound["tls"] = tls_config
        else:
            outbound["tls"] = {"enabled": True}
    transport = _build_transport(_first(query, "type") or "tcp", query, _first(query, "headerType", "header_type"))
    if transport:
        outbound["transport"] = transport
    label = _fragment_label(link, "Trojan proxy")
    return outbound, label, "trojan"


def _parse_hysteria2(link):
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
        "server_port": _parse_port(server_port),
        "password": password,
    }
    tls_config = _build_tls(query, "tls")
    if tls_config:
        outbound["tls"] = tls_config
    else:
        outbound["tls"] = {"enabled": True}
    obfs_type = _first(query, "obfs")
    if obfs_type:
        obfs_pass = _first(query, "obfs-password", "obfs_password")
        outbound["obfs"] = {"type": obfs_type}
        if obfs_pass:
            outbound["obfs"]["password"] = obfs_pass
    label = _fragment_label(link, "Hysteria2 proxy")
    return outbound, label, "hysteria2"


def _parse_tuic(link):
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
        "server_port": _parse_port(server_port),
        "uuid": uuid,
    }
    if password:
        outbound["password"] = password
    tls_config = _build_tls(query, "tls")
    if tls_config:
        outbound["tls"] = tls_config
    else:
        outbound["tls"] = {"enabled": True}
    label = _fragment_label(link, "TUIC proxy")
    return outbound, label, "tuic"


def _parse_http_proxy(link):
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
        "server_port": _parse_port(server_port),
    }
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    if username:
        outbound["username"] = username
    if password:
        outbound["password"] = password
    if is_https:
        tls_config = _build_tls(query, "tls")
        outbound["tls"] = tls_config if tls_config else {"enabled": True}
    label = _fragment_label(link, "HTTP proxy")
    return outbound, label, "http"


def _parse_socks5(link):
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
        "server_port": _parse_port(server_port),
        "version": "5",
    }
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    if username:
        outbound["username"] = username
    if password:
        outbound["password"] = password
    label = _fragment_label(link, "SOCKS5 proxy")
    return outbound, label, "socks5"


def _parse_ssr(link):
    payload = link[len("ssr://"):]
    decoded = _decode_base64_text(payload)
    main_part, separator, query_string = decoded.partition("/?")
    if not separator:
        main_part, separator, query_string = decoded.partition("?")
    parts = main_part.split(":")
    if len(parts) < 6:
        raise ValueError("SSR link has too few fields; expected server:port:protocol:method:obfs:password_b64")
    server = parts[0]
    server_port = _parse_port(parts[1])
    protocol = parts[2]
    method = parts[3]
    obfs = parts[4]
    password_b64 = ":".join(parts[5:])
    try:
        password = _decode_base64_text(password_b64)
    except ValueError as exc:
        raise ValueError(f"invalid SSR password: {exc}") from exc
    params = {}
    if query_string:
        for pair in query_string.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                params[key] = value
    def _decode_param(value):
        if not value:
            return ""
        try:
            return _decode_base64_text(value.replace("-", "+").replace("_", "/"))
        except ValueError:
            return value
    obfs_param = _decode_param(params.get("obfsparam", ""))
    proto_param = _decode_param(params.get("protoparam", ""))
    remarks = _decode_param(params.get("remarks", ""))
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
    label = remarks or _fragment_label(link, "ShadowsocksR proxy")
    return outbound, label, "shadowsocksr"


def _parse_wireguard(link):
    try:
        parsed = urlsplit(link)
        server = parsed.hostname
        server_port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid WireGuard URL: {exc}") from exc
    if not server:
        raise ValueError("WireGuard link is missing its endpoint")
    if server_port is None:
        server_port = 51820
    query = parse_qs(parsed.query, keep_blank_values=True)
    private_key = _required(query, "WireGuard private key", "private_key")
    public_key = _required(query, "WireGuard peer public key", "public_key")
    address = _first(query, "address", "local_address")
    local_address = [item.strip() for item in str(address).split(",") if item.strip()] if address else []
    allowed_ips = _first(query, "allowed_ips", "allowed-ips")
    pre_shared_key = _first(query, "pre_shared_key", "preshared_key", "psk")
    peer = {"server": server, "server_port": _parse_port(server_port), "public_key": str(public_key)}
    if pre_shared_key:
        peer["pre_shared_key"] = str(pre_shared_key)
    if allowed_ips:
        peer["allowed_ips"] = [item.strip() for item in str(allowed_ips).split(",") if item.strip()]
    outbound = {
        "type": "wireguard",
        "server": server,
        "server_port": _parse_port(server_port),
        "local_address": local_address,
        "private_key": str(private_key),
        "peers": [peer],
    }
    label = _fragment_label(link, "WireGuard tunnel")
    return outbound, label, "wireguard"


def _parse_naiveproxy(link):
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
        "server_port": _parse_port(server_port),
    }
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    if username:
        outbound["username"] = username
    if password:
        outbound["password"] = password
    label = _fragment_label(link, "NaiveProxy")
    return outbound, label, "naiveproxy"


_PARSERS: dict[str, Callable[[str], tuple[dict, str, str]]] = {
    "vmess": _parse_vmess,
    "vless": _parse_vless,
    "ss": _parse_ss,
    "ssr": _parse_ssr,
    "trojan": _parse_trojan,
    "hysteria2": _parse_hysteria2,
    "hy2": _parse_hysteria2,
    "tuic": _parse_tuic,
    "http": _parse_http_proxy,
    "https": _parse_http_proxy,
    "socks5": _parse_socks5,
    "wg": _parse_wireguard,
    "naive+https": _parse_naiveproxy,
    "naive+quic": _parse_naiveproxy,
}


_SUPPORTED_SCHEMES = "vmess://, vless://, ss://, ssr://, trojan://, hysteria2://, hy2://, tuic://, http://, https://, socks5://, wg://, naive+https://, or naive+quic://"


def parse_proxy_link(link):
    scheme = ""
    if "://" in link:
        scheme = link.split("://", 1)[0].lower()
    parser = _PARSERS.get(scheme)
    if parser is None:
        raise ValueError(f"unsupported link type; expected {_SUPPORTED_SCHEMES}")
    return parser(link)


def load_input(source: str, verify_ssl: bool = True) -> str:
    if source.startswith(("http://", "https://")):
        print(f"Fetching proxy links from URL: {source}", file=sys.stderr)
        req = urllib.request.Request(source, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        ssl_context = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()
        with urllib.request.urlopen(req, context=ssl_context, timeout=15) as response:
            text = response.read().decode("utf-8", errors="ignore")
    elif source == "-":
        text = sys.stdin.read()
    else:
        text = Path(source).read_text(encoding="utf-8-sig")

    stripped = text.strip()
    if stripped and "://" not in stripped:
        try:
            decoded = _decode_base64_text(stripped)
            if "://" in decoded:
                print("Base64-encoded subscription format detected and decoded.", file=sys.stderr)
                text = decoded
        except Exception:
            pass

    return text


def _sanitize_link(link: str) -> str:
    link = link.replace("\xa0", " ")
    if "email protected" in link.lower():
        return ""
    return link


def _parse_wireguard_conf_block(block_lines: list[str]) -> str | None:
    interface = {}
    peer = {}
    current_section = None
    for raw_line in block_lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.lower() == "[interface]":
            current_section = "interface"
            continue
        if line.lower() == "[peer]":
            current_section = "peer"
            continue
        if line.startswith("["):
            break
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if current_section == "interface":
            interface[key] = value
        elif current_section == "peer":
            peer[key] = value
    endpoint = peer.get("endpoint", "")
    private_key = interface.get("privatekey", "")
    public_key = peer.get("publickey", "")
    if not (endpoint and private_key and public_key):
        return None
    host, separator, port_str = endpoint.rpartition(":")
    if not separator:
        return None
    params = [f"private_key={private_key}", f"public_key={public_key}"]
    address = interface.get("address", "")
    if address:
        params.append(f"address={address.replace(' ', '')}")
    allowed_ips = peer.get("allowedips", "")
    if allowed_ips:
        params.append(f"allowed_ips={allowed_ips.replace(' ', '')}")
    psk = peer.get("presharedkey", "")
    if psk:
        params.append(f"pre_shared_key={psk}")
    return f"wg://{host}:{port_str}?{'&'.join(params)}"


def _extract_wireguard_conf_blocks(text: str) -> str:
    lines = text.splitlines()
    result = []
    i = 0
    while i < len(lines):
        if lines[i].strip().lower() == "[interface]":
            block_lines = [lines[i]]
            j = i + 1
            seen_peer = False
            while j < len(lines):
                line = lines[j].strip()
                if line.startswith("[") and line.lower() not in {"[peer]", "[interface]"}:
                    break
                if line.lower() == "[peer]":
                    seen_peer = True
                if not line and seen_peer:
                    break
                block_lines.append(lines[j])
                j += 1
            uri = _parse_wireguard_conf_block(block_lines)
            if uri:
                result.append(uri)
            i = j
        else:
            result.append(lines[i])
            i += 1
    return "\n".join(result)


def parse_links_text(text: str) -> tuple[list[ProxyInfo], list[dict]]:
    text = _extract_wireguard_conf_blocks(text)
    proxies: list[ProxyInfo] = []
    records: list[dict] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped_line = raw_line.strip()
        if not stripped_line or stripped_line.startswith("#") or stripped_line.startswith("//"):
            continue
        link = _sanitize_link(stripped_line)
        if not link:
            records.append(
                {
                    "stage": "parse",
                    "status": "filtered",
                    "kind": "sanitized_link",
                    "line_number": line_number,
                    "raw_line": raw_line,
                    "link": stripped_line,
                    "error": "filtered by _sanitize_link",
                }
            )
            continue
        try:
            outbound, label, protocol = parse_proxy_link(link)
            records.append(
                {
                    "stage": "parse",
                    "status": "ok",
                    "line_number": line_number,
                    "raw_line": raw_line,
                    "link": link,
                    "protocol": protocol,
                    "label": label,
                }
            )
            proxies.append(
                ProxyInfo(
                    link=link,
                    protocol=protocol,
                    label=label,
                    outbound=outbound,
                    diagnostics={
                        "parse": {
                            "status": "ok",
                            "line_number": line_number,
                            "raw_line": raw_line,
                        }
                    },
                )
            )
        except Exception as exc:
            error_text = str(exc)
            records.append(
                {
                    "stage": "parse",
                    "status": "failed",
                    "kind": "unsupported_transport" if (
                        error_text.startswith("unsupported transport type:")
                        or error_text.startswith("Xray XHTTP/splitHTTP transport is not supported")
                    ) else "malformed_link",
                    "line_number": line_number,
                    "raw_line": raw_line,
                    "link": link,
                    "error_type": type(exc).__name__,
                    "error": error_text,
                }
            )
    parse_failures = [record for record in records if record.get("status") == "failed"]
    if parse_failures:
        print(f"Warning: Skipped {len(parse_failures)} line(s) due to parsing errors.", file=sys.stderr)
        for error in parse_failures[:5]:
            print(f"  line {error['line_number']}: {error['error']}", file=sys.stderr)
        if len(parse_failures) > 5:
            print(f"  ... and {len(parse_failures) - 5} more.", file=sys.stderr)
    return proxies, records


def load_and_parse(source: str, verify_ssl: bool = True) -> tuple[list[ProxyInfo], list[dict]]:
    text = load_input(source, verify_ssl=verify_ssl)
    return parse_links_text(text)


def load_shadowmere_json(verify_ssl: bool = True) -> tuple[list[ProxyInfo], list[dict]]:
    import urllib.parse
    import urllib.request
    import base64
    import traceback
    from socksbox.models import ProxyInfo

    proxies: list[ProxyInfo] = []
    records: list[dict] = []
    source = "https://shadowmere.xyz/api/sub/?format=json"

    try:
        print(f"Fetching proxy links from URL: {source}", file=sys.stderr)
        req = urllib.request.Request(source, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        ssl_context = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()
        with urllib.request.urlopen(req, context=ssl_context, timeout=15) as response:
            text = response.read().decode("utf-8", errors="ignore")
    except Exception as exc:
        records.append({
            "source": source,
            "stage": "load",
            "status": "failed",
            "error": str(exc),
            "traceback": traceback.format_exc()
        })
        print(f"[error] {source}: {exc}", file=sys.stderr)
        return proxies, records

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        records.append({
            "source": source,
            "stage": "parse",
            "status": "failed",
            "kind": "invalid_json",
            "error": f"JSON decode error: {exc}"
        })
        print(f"[error] {source}: JSON decode error: {exc}", file=sys.stderr)
        return proxies, records

    if not isinstance(data, list):
        records.append({
            "source": source,
            "stage": "parse",
            "status": "failed",
            "kind": "invalid_json",
            "error": "JSON root is not a list"
        })
        print(f"[error] {source}: JSON root is not a list", file=sys.stderr)
        return proxies, records

    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            continue
        server = item.get("server")
        server_port = item.get("server_port")
        password = item.get("password")
        method = item.get("method")
        plugin = item.get("plugin") or ""
        plugin_opts = item.get("plugin_opts") or ""
        remarks = item.get("remarks") or ""

        if not server or not server_port or not password or not method:
            records.append({
                "source": source,
                "stage": "parse",
                "status": "failed",
                "kind": "missing_fields",
                "line_number": idx + 1,
                "error": f"item {idx} missing _required fields (server, server_port, password, method)"
            })
            continue

        try:
            # build outbound dict
            outbound = {
                "type": "shadowsocks",
                "server": str(server),
                "server_port": int(server_port),
                "method": str(method),
                "password": str(password),
            }
            if plugin:
                outbound["plugin"] = str(plugin)
            if plugin_opts:
                outbound["plugin_opts"] = str(plugin_opts)

            # Format ss link
            creds = f"{method}:{password}"
            creds_b64 = base64.b64encode(creds.encode("utf-8")).decode("utf-8")
            link = f"ss://{creds_b64}@{server}:{server_port}"
            query_parts = []
            if plugin:
                if plugin_opts:
                    query_parts.append(f"plugin={urllib.parse.quote(f'{plugin};{plugin_opts}')}")
                else:
                    query_parts.append(f"plugin={urllib.parse.quote(plugin)}")
            if query_parts:
                link += f"?{'&'.join(query_parts)}"
            if remarks:
                link += f"#{urllib.parse.quote(remarks)}"

            records.append({
                "source": source,
                "stage": "parse",
                "status": "ok",
                "line_number": idx + 1,
                "link": link,
                "protocol": "shadowsocks",
                "label": remarks,
            })
            proxies.append(
                ProxyInfo(
                    link=link,
                    protocol="shadowsocks",
                    label=remarks,
                    outbound=outbound,
                    diagnostics={
                        "parse": {
                            "status": "ok",
                            "line_number": idx + 1,
                            "source": source,
                        }
                    },
                )
            )
        except Exception as exc:
            records.append({
                "source": source,
                "stage": "parse",
                "status": "failed",
                "kind": "malformed_shadowsocks_json",
                "line_number": idx + 1,
                "error": str(exc),
            })
    print(f"[ok] {source}: {len(proxies)} proxies", file=sys.stderr)
    return proxies, records


def load_proxyscrape_json(verify_ssl: bool = True) -> tuple[list[ProxyInfo], list[dict]]:
    import urllib.request
    import traceback
    import gzip
    import zlib
    from socksbox.models import ProxyInfo

    proxies: list[ProxyInfo] = []
    records: list[dict] = []

    source = (
        "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies"
        "&proxy_format=protocolipport&format=json&protocol=socks5%2Csocks4&anonymity=elite"
        "&country=af%2Cal%2Cdz%2Cad%2Cao%2Car%2Cam%2Cau%2Cat%2Caz%2Cbd%2Cby%2Cbe%2Cbj"
        "%2Cbm%2Cbt%2Cbo%2Cbw%2Cbg%2Cbf%2Cbi%2Ckh%2Ccm%2Cca%2Ctd%2Ccl%2Ccn%2Cco%2Ccg"
        "%2Ccr%2Chr%2Ccy%2Ccz%2Cdk%2Cdo%2Cec%2Ceg%2Csv%2Cgq%2Cee%2Csz%2Et%2Cfj%2Cfi"
        "%2Cfr%2Cgm%2Cge%2Cde%2Cgh%2Cgi%2Cgr%2Cgu%2Cgt%2Cgn%2Cht%2Chn%2Chk%2Chu%2Cin"
        "%2Cid%2Cir%2Ciq%2Cie%2Cil%2Cit%2Cjm%2Cjp%2Cjo%2Ckz%2Cke%2Ckr%2Ckg%2Clv%2Clb"
        "%2Cls%2Clt%2Cmg%2Cmw%2Cmy%2Cmv%2Cml%2Cmt%2Cmu%2Cmx%2Cmd%2Cmn%2Cme%2Cma%2Cmz"
        "%2Cmm%2Cna%2Cnp%2Cnl%2Cnz%2Cni%2Cng%2Cmk%2Cno%2Cpk%2Cps%2Cpa%2Cpy%2Cpe%2Cph"
        "%2Cpl%2Cpt%2Cpr%2Cqa%2Cro%2Crw%2Ckn%2Csa%2Csn%2Crs%2Csc%2Csl%2Csg%2Csk%2Csi"
        "%2Cso%2Cza%2Ces%2Clk%2Csd%2Cse%2Cch%2Csy%2Ctw%2Ctj%2Ctz%2Cth%2Ctl%2Ctg%2Ctn"
        "%2Ctr%2Cug%2Cua%2Cae%2Cgb%2Cus%2Cuy%2Cuz%2Cve%2Cvn%2Cvi%2Cye%2Czw"
    )

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0",
        "Accept": "*/*",
        "Accept-Language": "en-CA,en-US;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Referer": "https://proxyscrape.com/",
        "Origin": "https://proxyscrape.com",
        "DNT": "1",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }

    try:
        print(f"Fetching proxy links from URL: {source}", file=sys.stderr)
        req = urllib.request.Request(source, headers=headers)
        ssl_context = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()
        with urllib.request.urlopen(req, context=ssl_context, timeout=15) as response:
            content_encoding = response.info().get("Content-Encoding")
            data = response.read()
            if content_encoding == "gzip":
                data = gzip.decompress(data)
            elif content_encoding == "deflate":
                data = zlib.decompress(data)
            text = data.decode("utf-8", errors="ignore")
    except Exception as exc:
        records.append({
            "source": source,
            "stage": "load",
            "status": "failed",
            "error": str(exc),
            "traceback": traceback.format_exc()
        })
        print(f"[error] {source}: {exc}", file=sys.stderr)
        return proxies, records

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        records.append({
            "source": source,
            "stage": "parse",
            "status": "failed",
            "kind": "invalid_json",
            "error": f"JSON decode error: {exc}"
        })
        print(f"[error] {source}: JSON decode error: {exc}", file=sys.stderr)
        return proxies, records

    if not isinstance(data, dict) or "proxies" not in data:
        records.append({
            "source": source,
            "stage": "parse",
            "status": "failed",
            "kind": "invalid_json",
            "error": "JSON root is not a dictionary with 'proxies' key"
        })
        print(f"[error] {source}: JSON root is not a dict with 'proxies'", file=sys.stderr)
        return proxies, records

    proxies_list = data["proxies"]
    if not isinstance(proxies_list, list):
        records.append({
            "source": source,
            "stage": "parse",
            "status": "failed",
            "kind": "invalid_json",
            "error": "'proxies' field is not a list"
        })
        print(f"[error] {source}: 'proxies' field is not a list", file=sys.stderr)
        return proxies, records

    for idx, item in enumerate(proxies_list):
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        port = item.get("port")
        protocol = item.get("protocol") or "socks5"
        link = item.get("proxy")

        if not ip or port is None:
            records.append({
                "source": source,
                "stage": "parse",
                "status": "failed",
                "kind": "missing_fields",
                "line_number": idx + 1,
                "error": f"item {idx} missing _required fields (ip, port)"
            })
            continue

        if not link:
            link = f"{protocol}://{ip}:{port}"

        try:
            outbound = {
                "type": "socks",
                "server": str(ip),
                "server_port": int(port),
                "version": "4" if protocol.lower() == "socks4" else "5",
            }

            ip_data = item.get("ip_data") or {}
            country_code = ip_data.get("country_code") or ""
            country = ip_data.get("country") or ""
            city = ip_data.get("city") or ""
            org = ip_data.get("as") or ip_data.get("asname") or ""

            label = f"ProxyScrape {protocol.upper()} {ip}:{port}"

            records.append({
                "source": source,
                "stage": "parse",
                "status": "ok",
                "line_number": idx + 1,
                "link": link,
                "protocol": protocol,
                "label": label,
            })
            proxies.append(
                ProxyInfo(
                    link=link,
                    protocol=protocol,
                    label=label,
                    outbound=outbound,
                    ip=str(ip),
                    country=str(country),
                    country_code=str(country_code),
                    city=str(city),
                    org=str(org),
                    diagnostics={
                        "parse": {
                            "status": "ok",
                            "line_number": idx + 1,
                            "source": source,
                        }
                    },
                )
            )
        except Exception as exc:
            records.append({
                "source": source,
                "stage": "parse",
                "status": "failed",
                "kind": "malformed_proxyscrape_json",
                "line_number": idx + 1,
                "error": str(exc),
            })
    print(f"[ok] {source}: {len(proxies)} proxies", file=sys.stderr)
    return proxies, records

