from __future__ import annotations

from socksbox.exporters.base import BaseExporter, Exporter
from socksbox.exporters.grouped import GroupedExporter
from socksbox.exporters.json_exporter import (
    ConfigExporter,
    DiagnosticsExporter,
    SummaryExporter,
)
from socksbox.exporters.txt import (
    AllTxtExporter,
    Top10TxtExporter,
    WorkingTxtExporter,
)

DEFAULT_EXPORTERS: list[Exporter] = [
    AllTxtExporter(),
    WorkingTxtExporter(),
    Top10TxtExporter(),
    GroupedExporter(),
    ConfigExporter(),
    SummaryExporter(),
    DiagnosticsExporter(),
]

__all__ = [
    "BaseExporter",
    "Exporter",
    "AllTxtExporter",
    "WorkingTxtExporter",
    "Top10TxtExporter",
    "GroupedExporter",
    "ConfigExporter",
    "SummaryExporter",
    "DiagnosticsExporter",
    "DEFAULT_EXPORTERS",
]
