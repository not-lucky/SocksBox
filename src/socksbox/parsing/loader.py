from __future__ import annotations

import ssl
import sys
import urllib.request
from pathlib import Path
from socksbox.models import ProxyInfo, ProxyInfoBuilder
from socksbox.parsing.helpers import decode_base64_text
from socksbox.parsing.registry import GLOBAL_REGISTRY


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
            decoded = decode_base64_text(stripped)
            if "://" in decoded:
                print("Base64-encoded subscription format detected and decoded.", file=sys.stderr)
                text = decoded
        except Exception:
            pass

    return text


def sanitize_link(link: str) -> str:
    link = link.replace("\xa0", " ")
    if "email protected" in link.lower():
        return ""
    return link


def parse_wireguard_conf_block(block_lines: list[str]) -> str | None:
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


def extract_wireguard_conf_blocks(text: str) -> str:
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
            uri = parse_wireguard_conf_block(block_lines)
            if uri:
                result.append(uri)
            i = j
        else:
            result.append(lines[i])
            i += 1
    return "\n".join(result)


def parse_links_text(text: str) -> tuple[list[ProxyInfo], list[dict]]:
    text = extract_wireguard_conf_blocks(text)
    proxies: list[ProxyInfo] = []
    records: list[dict] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped_line = raw_line.strip()
        if not stripped_line or stripped_line.startswith("#") or stripped_line.startswith("//"):
            continue
        link = sanitize_link(stripped_line)
        if not link:
            records.append(
                {
                    "stage": "parse",
                    "status": "filtered",
                    "kind": "sanitized_link",
                    "line_number": line_number,
                    "raw_line": raw_line,
                    "link": stripped_line,
                    "error": "filtered by sanitize_link",
                }
            )
            continue
        try:
            outbound, label, protocol = GLOBAL_REGISTRY.parse_proxy_link(link)
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
                ProxyInfoBuilder()
                .with_link(link)
                .with_protocol(protocol)
                .with_label(label)
                .with_outbound(outbound)
                .with_diagnostic("parse", {
                    "status": "ok",
                    "line_number": line_number,
                    "raw_line": raw_line,
                })
                .build()
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
