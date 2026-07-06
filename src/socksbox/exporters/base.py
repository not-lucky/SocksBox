from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, List, Protocol, runtime_checkable

from socksbox.models import ProxyInfo


class ExportVisitor(ABC):
    """Visitor Pattern: Interface for visiting proxy data formats."""

    @abstractmethod
    def visit_working(self, proxies: list[ProxyInfo]) -> Any:
        ...

    @abstractmethod
    def visit_failed(self, proxies: list[ProxyInfo]) -> Any:
        ...

    @abstractmethod
    def visit_config(self, config: dict[str, Any]) -> Any:
        ...

    @abstractmethod
    def visit_issues(self, issues: list[dict[str, Any]]) -> Any:
        ...


@runtime_checkable
class Exporter(Protocol):
    """Protocol for an output artifact exporter."""

    def write(
        self,
        proxies: list[ProxyInfo],
        config: dict[str, Any],
        output_dir: Path,
        start_port: int,
        issues: list[dict[str, Any]],
    ) -> None:
        ...


class BaseExporter(ABC):
    """Optional base class for concrete exporters."""

    @staticmethod
    def working(proxies: list[ProxyInfo]) -> list[ProxyInfo]:
        """Return proxies whose latency is finite."""
        return [p for p in proxies if p.working]

    @staticmethod
    def failed(proxies: list[ProxyInfo]) -> list[ProxyInfo]:
        """Return proxies that did not succeed."""
        return [p for p in proxies if not p.working]

    @abstractmethod
    def write(
        self,
        proxies: list[ProxyInfo],
        config: dict[str, Any],
        output_dir: Path,
        start_port: int,
        issues: list[dict[str, Any]],
    ) -> None:
        """Implementing exporters must override this method."""
        raise NotImplementedError


class CompositeExporter(BaseExporter):
    """Composite Pattern: Treats a collection of exporters as a single exporter."""

    def __init__(self, children: List[Exporter] | None = None) -> None:
        self._children: List[Exporter] = children or []

    def add(self, exporter: Exporter) -> None:
        if exporter not in self._children:
            self._children.append(exporter)

    def remove(self, exporter: Exporter) -> None:
        if exporter in self._children:
            self._children.remove(exporter)

    def __len__(self) -> int:
        return len(self._children)

    def __iter__(self):
        return iter(self._children)

    def __getitem__(self, index: int) -> Exporter:
        return self._children[index]

    def write(
        self,
        proxies: list[ProxyInfo],
        config: dict[str, Any],
        output_dir: Path,
        start_port: int,
        issues: list[dict[str, Any]],
    ) -> None:
        for child in self._children:
            child.write(proxies, config, output_dir, start_port, issues)
