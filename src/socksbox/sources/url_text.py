"""Plain-text URL source adapter for SocksBox."""

from __future__ import annotations

from socksbox.parser import load_and_parse
from socksbox.sources.base import LoadResult


class UrlTextSource:
    """Load and parse a plain-text subscription URL.

    This adapter wraps :func:`socksbox.parser.load_and_parse` and self-labels
    every diagnostic record with the source URL.
    """

    url: str = (
        "https://github.com/ebrasha/free-v2ray-public-list/raw/refs/heads/main/"
        "V2Ray-Config-By-EbraSha.txt"
    )
    prints_summary: bool = True

    def __init__(self, url: str | None = None) -> None:
        if url is not None:
            self.url = url

    def load(self, verify_ssl: bool = True) -> LoadResult:
        """Fetch and parse the configured plain-text URL.

        Args:
            verify_ssl: Whether to verify TLS certificates when fetching data.

        Returns:
            A :class:`~socksbox.sources.base.LoadResult` containing the parsed
            proxies and diagnostic records.
        """
        proxies, records = load_and_parse(self.url, verify_ssl=verify_ssl)
        labelled_records = []
        for record in records:
            enriched = dict(record)
            enriched.setdefault("source", self.url)
            labelled_records.append(enriched)
        return LoadResult(proxies=proxies, records=labelled_records)


DEFAULT_URL_TEXT_SOURCE = UrlTextSource()
