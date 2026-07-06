from __future__ import annotations

from dataclasses import dataclass, field
import copy
from typing import Any, Self


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

    def clone(self, **overrides: Any) -> ProxyInfo:
        """Prototype pattern: clone and override attributes."""
        kwargs = {
            "link": self.link,
            "protocol": self.protocol,
            "label": self.label,
            "outbound": copy.deepcopy(self.outbound),
            "latency_ms": self.latency_ms,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "region": self.region,
            "org": self.org,
            "ip": self.ip,
            "timezone": self.timezone,
            "raw_geo": copy.deepcopy(self.raw_geo),
            "diagnostics": copy.deepcopy(self.diagnostics),
        }
        kwargs.update(overrides)
        return ProxyInfo(**kwargs)


class ProxyInfoBuilder:
    """Builder pattern for ProxyInfo objects."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> Self:
        self._link = ""
        self._protocol = ""
        self._label = ""
        self._outbound: dict = {}
        self._latency_ms = float("inf")
        self._country = ""
        self._country_code = ""
        self._city = ""
        self._region = ""
        self._org = ""
        self._ip = ""
        self._timezone = ""
        self._raw_geo: dict = {}
        self._diagnostics: dict[str, Any] = {}
        return self

    def with_link(self, link: str) -> Self:
        self._link = link
        return self

    def with_protocol(self, protocol: str) -> Self:
        self._protocol = protocol
        return self

    def with_label(self, label: str) -> Self:
        self._label = label
        return self

    def with_outbound(self, outbound: dict) -> Self:
        self._outbound = outbound
        return self

    def with_latency(self, latency_ms: float) -> Self:
        self._latency_ms = latency_ms
        return self

    def with_geo(
        self,
        country: str = "",
        country_code: str = "",
        city: str = "",
        region: str = "",
        org: str = "",
        ip: str = "",
        timezone: str = "",
        raw_geo: dict | None = None,
    ) -> Self:
        self._country = country
        self._country_code = country_code
        self._city = city
        self._region = region
        self._org = org
        self._ip = ip
        self._timezone = timezone
        if raw_geo is not None:
            self._raw_geo = raw_geo
        return self

    def with_diagnostic(self, stage: str, data: dict[str, Any]) -> Self:
        self._diagnostics[stage] = data
        return self

    def with_diagnostics(self, diagnostics: dict[str, Any]) -> Self:
        self._diagnostics.update(diagnostics)
        return self

    def build(self) -> ProxyInfo:
        return ProxyInfo(
            link=self._link,
            protocol=self._protocol,
            label=self._label,
            outbound=self._outbound,
            latency_ms=self._latency_ms,
            country=self._country,
            country_code=self._country_code,
            city=self._city,
            region=self._region,
            org=self._org,
            ip=self._ip,
            timezone=self._timezone,
            raw_geo=self._raw_geo,
            diagnostics=self._diagnostics,
        )
