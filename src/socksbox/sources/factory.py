from __future__ import annotations

from typing import Dict, Type
from socksbox.sources.base import BaseSource
from socksbox.sources.url_text import UrlTextSource
from socksbox.sources.shadowmere import ShadowmereSource
from socksbox.sources.proxyscrape import ProxyscrapeSource


class SourceFactory:
    """Abstract Factory pattern: creates sources by registered names."""

    def __init__(self) -> None:
        self._registry: Dict[str, Type[BaseSource]] = {}
        # Register defaults
        self.register("url_text", UrlTextSource)
        self.register("shadowmere", ShadowmereSource)
        self.register("proxyscrape", ProxyscrapeSource)

    def register(self, name: str, source_cls: Type[BaseSource]) -> None:
        self._registry[name.lower()] = source_cls

    def create(self, name: str, **kwargs) -> BaseSource:
        source_cls = self._registry.get(name.lower())
        if source_cls is None:
            raise ValueError(f"Unknown source type: {name}")
        return source_cls(**kwargs)

    def create_all_defaults(self) -> list[BaseSource]:
        return [
            self.create("url_text"),
            self.create("shadowmere"),
            self.create("proxyscrape"),
        ]


GLOBAL_SOURCE_FACTORY = SourceFactory()
