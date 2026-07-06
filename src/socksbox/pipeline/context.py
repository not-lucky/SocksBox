from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List
from socksbox.models import ProxyInfo


@dataclass(frozen=True)
class PipelineSnapshot:
    """Memento pattern: Snapshot of the pipeline state at a point in time."""

    proxies: list[ProxyInfo]
    parse_records: list[dict]
    issues: list[dict]
    config: dict[str, Any] | None


@dataclass
class PipelineContext:
    """The context objects containing the pipeline state during execution."""

    proxies: list[ProxyInfo] = field(default_factory=list)
    parse_records: list[dict] = field(default_factory=list)
    issues: list[dict] = field(default_factory=list)
    config: dict[str, Any] | None = None
    output_dir: Path | None = None
    settings: Dict[str, Any] = field(default_factory=dict)

    def save_snapshot(self) -> PipelineSnapshot:
        """Saves a snapshot of current state (Memento pattern)."""
        return PipelineSnapshot(
            proxies=[p.clone() for p in self.proxies],
            parse_records=copy.deepcopy(self.parse_records),
            issues=copy.deepcopy(self.issues),
            config=copy.deepcopy(self.config) if self.config is not None else None,
        )

    def restore_snapshot(self, snapshot: PipelineSnapshot) -> None:
        """Restores state from a snapshot (Memento pattern)."""
        self.proxies = [p.clone() for p in snapshot.proxies]
        self.parse_records = copy.deepcopy(snapshot.parse_records)
        self.issues = copy.deepcopy(snapshot.issues)
        self.config = copy.deepcopy(snapshot.config) if snapshot.config is not None else None
