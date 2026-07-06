"""Shadowmere JSON source adapter for SocksBox using Template Method."""

from __future__ import annotations

import base64
import json
import ssl
import sys
import urllib.parse
import urllib.request
from socksbox.models import ProxyInfo, ProxyInfoBuilder
from socksbox.sources.base import BaseSource


class ShadowmereSource(BaseSource):
    """Load and parse proxies from the Shadowmere JSON API."""

    url: str = "https://shadowmere.xyz/api/sub/?format=json"
    prints_summary: bool = False

    def _fetch(self, verify_ssl: bool) -> bytes:
        print(f"Fetching proxy links from URL: {self.url}", file=sys.stderr)
        req = urllib.request.Request(self.url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        ssl_context = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()
        with urllib.request.urlopen(req, context=ssl_context, timeout=15) as response:
            return response.read()

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

        if not isinstance(parsed_data, list):
            records.append({
                "source": self.url,
                "stage": "parse",
                "status": "failed",
                "kind": "invalid_json",
                "error": "JSON root is not a list"
            })
            print(f"[error] {self.url}: JSON root is not a list", file=sys.stderr)
            return proxies, records

        for idx, item in enumerate(parsed_data):
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
                    "source": self.url,
                    "stage": "parse",
                    "status": "failed",
                    "kind": "missing_fields",
                    "line_number": idx + 1,
                    "error": f"item {idx} missing required fields (server, server_port, password, method)"
                })
                continue

            try:
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
                    "source": self.url,
                    "stage": "parse",
                    "status": "ok",
                    "line_number": idx + 1,
                    "link": link,
                    "protocol": "shadowsocks",
                    "label": remarks,
                })
                proxies.append(
                    ProxyInfoBuilder()
                    .with_link(link)
                    .with_protocol("shadowsocks")
                    .with_label(remarks)
                    .with_outbound(outbound)
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
                    "kind": "malformed_shadowsocks_json",
                    "line_number": idx + 1,
                    "error": str(exc),
                })
        print(f"[ok] {self.url}: {len(proxies)} proxies", file=sys.stderr)
        return proxies, records


DEFAULT_SHADOWMERE_SOURCE = ShadowmereSource()
