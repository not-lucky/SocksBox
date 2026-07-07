"""ProxyScrape JSON source adapter for SocksBox using Template Method."""

from __future__ import annotations

import gzip
import json
import ssl
import sys
import urllib.request
import zlib
from socksbox.models import ProxyInfo, ProxyInfoBuilder
from socksbox.sources.base import BaseSource


class ProxyscrapeSource(BaseSource):
    """Load and parse proxies from the ProxyScrape JSON API."""

    url: str = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=json"
    prints_summary: bool = False

    def _fetch(self, verify_ssl: bool) -> bytes:
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
        print(f"Fetching proxy links from URL: {self.url}", file=sys.stderr)
        req = urllib.request.Request(self.url, headers=headers)
        ssl_context = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()
        with urllib.request.urlopen(req, context=ssl_context, timeout=15) as response:
            content_encoding = response.info().get("Content-Encoding")
            data = response.read()
            if content_encoding == "gzip":
                data = gzip.decompress(data)
            elif content_encoding == "deflate":
                data = zlib.decompress(data)
            return data

    def _parse(self, data: str) -> tuple[list[ProxyInfo], list[dict]]:
        proxies: list[ProxyInfo] = []
        records: list[dict] = []

        try:
            parsed_data = json.loads(data)
        except json.JSONDecodeError as exc:
            records.append({
                "source": self.url,
                "stage": "parse",
                "status": "failed",
                "kind": "invalid_json",
                "error": f"JSON decode error: {exc}"
            })
            print(f"[error] {self.url}: JSON decode error: {exc}", file=sys.stderr)
            return proxies, records

        if not isinstance(parsed_data, dict) or "proxies" not in parsed_data:
            records.append({
                "source": self.url,
                "stage": "parse",
                "status": "failed",
                "kind": "invalid_json",
                "error": "JSON root is not a dictionary with 'proxies' key"
            })
            print(f"[error] {self.url}: JSON root is not a dict with 'proxies'", file=sys.stderr)
            return proxies, records

        proxies_list = parsed_data["proxies"]
        if not isinstance(proxies_list, list):
            records.append({
                "source": self.url,
                "stage": "parse",
                "status": "failed",
                "kind": "invalid_json",
                "error": "'proxies' field is not a list"
            })
            print(f"[error] {self.url}: 'proxies' field is not a list", file=sys.stderr)
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
                    "source": self.url,
                    "stage": "parse",
                    "status": "failed",
                    "kind": "missing_fields",
                    "line_number": idx + 1,
                    "error": f"item {idx} missing required fields (ip, port)"
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
                    "source": self.url,
                    "stage": "parse",
                    "status": "ok",
                    "line_number": idx + 1,
                    "link": link,
                    "protocol": protocol,
                    "label": label,
                })
                proxies.append(
                    ProxyInfoBuilder()
                    .with_link(link)
                    .with_protocol(protocol)
                    .with_label(label)
                    .with_outbound(outbound)
                    .with_geo(
                        country=str(country),
                        country_code=str(country_code),
                        city=str(city),
                        org=str(org),
                        ip=str(ip),
                    )
                    .with_diagnostic("parse", {
                        "status": "ok",
                        "line_number": idx + 1,
                        "source": self.url,
                    })
                    .build()
                )
            except Exception as exc:
                records.append({
                    "source": self.url,
                    "stage": "parse",
                    "status": "failed",
                    "kind": "malformed_proxyscrape_json",
                    "line_number": idx + 1,
                    "error": str(exc),
                })
        print(f"[ok] {self.url}: {len(proxies)} proxies", file=sys.stderr)
        return proxies, records


DEFAULT_PROXYSCRAPE_SOURCE = ProxyscrapeSource()
