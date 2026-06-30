from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from socksbox.models import ProxyInfo


@runtime_checkable
class Exporter(Protocol):
    """Protocol for an output artifact exporter.

    Implementations receive the full result set and write a single artifact
    (or cohesive group of artifacts) under ``output_dir``.
    """

    def write(
        self,
        proxies: list[ProxyInfo],
        config: dict[str, Any],
        output_dir: Path,
        start_port: int,
        issues: list[dict[str, Any]],
    ) -> None:
        """Write this exporter's artifact(s) to ``output_dir``.

        Args:
            proxies: All proxies produced by the pipeline.
            config: The resolved configuration object.
            output_dir: Directory where artifacts should be written.
            start_port: Base port assigned to the first proxy.
            issues: Diagnostics/issues collected during execution.
        """
        ...


class BaseExporter(ABC):
    """Optional base class for concrete exporters.

    Provides small helpers for working with the proxy list without
    importing ``exporter.py`` or other concrete modules.
    """

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
