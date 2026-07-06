from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ParserStrategy(Protocol):
    """Strategy pattern: each protocol parser implements this interface."""

    @property
    def schemes(self) -> tuple[str, ...]:
        """The schemes supported by this parser (e.g. ('vmess',))."""
        ...

    def parse(self, link: str) -> tuple[dict, str, str]:
        """Parse the link and return (outbound_dict, label, protocol_name)."""
        ...
