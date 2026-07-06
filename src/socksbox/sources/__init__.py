"""SocksBox source adapters and default registry."""

from __future__ import annotations

from socksbox.sources.base import BaseSource, LoadResult, Source
from socksbox.sources.factory import SourceFactory, GLOBAL_SOURCE_FACTORY
from socksbox.sources.proxyscrape import DEFAULT_PROXYSCRAPE_SOURCE, ProxyscrapeSource
from socksbox.sources.shadowmere import DEFAULT_SHADOWMERE_SOURCE, ShadowmereSource
from socksbox.sources.url_text import DEFAULT_URL_TEXT_SOURCE, UrlTextSource

DEFAULT_SOURCES: list[Source] = [
    DEFAULT_URL_TEXT_SOURCE,
    DEFAULT_SHADOWMERE_SOURCE,
    DEFAULT_PROXYSCRAPE_SOURCE,
]

__all__ = [
    "BaseSource",
    "LoadResult",
    "Source",
    "SourceFactory",
    "GLOBAL_SOURCE_FACTORY",
    "DEFAULT_SOURCES",
    "ProxyscrapeSource",
    "ShadowmereSource",
    "UrlTextSource",
]
