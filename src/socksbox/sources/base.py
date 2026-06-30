"""Base protocol and shared return type for SocksBox source adapters."""

from __future__ import annotations

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
    """Protocol implemented by every SocksBox source adapter.

    A source adapter knows how to fetch and parse proxies from a specific
    upstream (for example a JSON API or a plaintext subscription URL).  The
    ``load`` method must return the parsed :class:`~socksbox.models.ProxyInfo`
    instances together with a list of parse/load records for diagnostics.
    """

    def load(self, verify_ssl: bool = True) -> LoadResult:
        """Fetch and parse proxies from this source.

        Args:
            verify_ssl: Whether to verify TLS certificates when fetching data.

        Returns:
            A :class:`LoadResult` containing the parsed proxies and diagnostic
            records.
        """
        ...
