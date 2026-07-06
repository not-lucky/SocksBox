from __future__ import annotations

from typing import Dict
from socksbox.parsing.base import ParserStrategy
from socksbox.parsing.protocols.vmess import VMessParser
from socksbox.parsing.protocols.vless import VLessParser
from socksbox.parsing.protocols.shadowsocks import ShadowsocksParser
from socksbox.parsing.protocols.trojan import TrojanParser
from socksbox.parsing.protocols.hysteria2 import Hysteria2Parser
from socksbox.parsing.protocols.tuic import TuicParser
from socksbox.parsing.protocols.http import HttpParser
from socksbox.parsing.protocols.socks5 import Socks5Parser
from socksbox.parsing.protocols.ssr import SsrParser
from socksbox.parsing.protocols.wireguard import WireguardParser
from socksbox.parsing.protocols.naiveproxy import NaiveproxyParser


class ParserRegistry:
    """Flyweight pattern: parser instances are reused.
    Factory Method: create_parser(scheme) returns the requested parser strategy.
    """

    def __init__(self) -> None:
        self._parsers: Dict[str, ParserStrategy] = {}
        # Pre-populate defaults (Flyweight)
        for parser in [
            VMessParser(),
            VLessParser(),
            ShadowsocksParser(),
            TrojanParser(),
            Hysteria2Parser(),
            TuicParser(),
            HttpParser(),
            Socks5Parser(),
            SsrParser(),
            WireguardParser(),
            NaiveproxyParser(),
        ]:
            self.register(parser)

    def register(self, parser: ParserStrategy) -> None:
        for scheme in parser.schemes:
            self._parsers[scheme.lower()] = parser

    def create_parser(self, scheme: str) -> ParserStrategy:
        """Factory Method to get parser for a scheme."""
        parser = self._parsers.get(scheme.lower())
        if parser is None:
            supported = ", ".join(f"{s}://" for s in self._parsers.keys())
            raise ValueError(f"unsupported link type; expected {supported}")
        return parser

    def parse_proxy_link(self, link: str) -> tuple[dict, str, str]:
        scheme = ""
        if "://" in link:
            scheme = link.split("://", 1)[0].lower()
        parser = self.create_parser(scheme)
        return parser.parse(link)


# Singleton registry instance for easy usage
GLOBAL_REGISTRY = ParserRegistry()
