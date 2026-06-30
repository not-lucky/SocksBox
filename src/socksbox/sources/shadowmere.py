"""Shadowmere JSON source adapter for SocksBox."""

from __future__ import annotations

from socksbox.parser import load_shadowmere_json
from socksbox.sources.base import LoadResult


class ShadowmereSource:
    """Load and parse proxies from the Shadowmere JSON API.

    This adapter wraps :func:`socksbox.parser.load_shadowmere_json` and
    self-labels every diagnostic record with the source URL.
    """

    url: str = "https://shadowmere.xyz/api/sub/?format=json"
    prints_summary: bool = False

    def load(self, verify_ssl: bool = True) -> LoadResult:
        """Fetch and parse Shadowmere JSON.

        Args:
            verify_ssl: Whether to verify TLS certificates when fetching data.

        Returns:
            A :class:`~socksbox.sources.base.LoadResult` containing the parsed
            proxies and diagnostic records.
        """
        proxies, records = load_shadowmere_json(verify_ssl=verify_ssl)
        labelled_records = []
        for record in records:
            enriched = dict(record)
            enriched.setdefault("source", self.url)
            labelled_records.append(enriched)
        return LoadResult(proxies=proxies, records=labelled_records)


DEFAULT_SHADOWMERE_SOURCE = ShadowmereSource()
