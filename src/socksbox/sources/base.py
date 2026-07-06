"""Base protocol, base class (Template Method pattern), and shared return type for SocksBox source adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from socksbox.models import ProxyInfo


@dataclass(frozen=True)
class LoadResult:
    """Return value produced by a :class:`Source`.

    ``LoadResult`` behaves like a ``(proxies, records)`` tuple and can be
    unpacked, while still providing named access to the two components.
    """

    proxies: list[ProxyInfo]
    records: list[dict]

    def __iter__(self):
        return iter((self.proxies, self.records))


@runtime_checkable
class Source(Protocol):
    """Protocol implemented by every SocksBox source adapter."""

    url: str
    prints_summary: bool

    def load(self, verify_ssl: bool = True) -> LoadResult:
        """Fetch and parse proxies from this source."""
        ...


class BaseSource(ABC):
    """Template Method pattern: defines the skeleton of the loading algorithm."""

    url: str = ""
    prints_summary: bool = True

    def load(self, verify_ssl: bool = True) -> LoadResult:
        """The template method defining the loading steps."""
        raw_data = self._fetch(verify_ssl)
        decoded = self._decode(raw_data)
        proxies, records = self._parse(decoded)
        labelled_records = self._label_records(records)
        return LoadResult(proxies=proxies, records=labelled_records)

    @abstractmethod
    def _fetch(self, verify_ssl: bool) -> bytes:
        """Hook: Fetch raw bytes from the source."""
        ...

    def _decode(self, raw: bytes) -> str:
        """Hook: Decode raw bytes into string."""
        return raw.decode("utf-8", errors="ignore")

    @abstractmethod
    def _parse(self, data: str) -> tuple[list[ProxyInfo], list[dict]]:
        """Hook: Parse decoded data into proxies and records."""
        ...

    def _label_records(self, records: list[dict]) -> list[dict]:
        """Hook: Label records with the source URL."""
        labelled = []
        for r in records:
            enriched = dict(r)
            enriched.setdefault("source", self.url)
            labelled.append(enriched)
        return labelled
