from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProxyInfo:
    link: str
    protocol: str
    label: str
    outbound: dict
    latency_ms: float = float("inf")
    country: str = ""
    country_code: str = ""
    city: str = ""
    region: str = ""
    org: str = ""
    ip: str = ""
    timezone: str = ""
    raw_geo: dict = field(default_factory=dict)
    diagnostics: dict[str, Any] = field(default_factory=dict)

    @property
    def working(self) -> bool:
        return self.latency_ms != float("inf")
