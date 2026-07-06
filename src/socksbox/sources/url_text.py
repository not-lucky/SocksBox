"""Plain-text URL source adapter for SocksBox using Template Method."""

from __future__ import annotations

from socksbox.models import ProxyInfo
from socksbox.parsing.loader import load_input, parse_links_text
from socksbox.sources.base import BaseSource


class UrlTextSource(BaseSource):
    """Load and parse a plain-text subscription URL."""

    url: str = (
        "https://github.com/ebrasha/free-v2ray-public-list/raw/refs/heads/main/"
        "V2Ray-Config-By-EbraSha.txt"
    )
    prints_summary: bool = True

    def __init__(self, url: str | None = None) -> None:
        if url is not None:
            self.url = url

    def _fetch(self, verify_ssl: bool) -> bytes:
        return load_input(self.url, verify_ssl=verify_ssl).encode("utf-8")

    def _parse(self, data: str) -> tuple[list[ProxyInfo], list[dict]]:
        return parse_links_text(data)


DEFAULT_URL_TEXT_SOURCE = UrlTextSource()
