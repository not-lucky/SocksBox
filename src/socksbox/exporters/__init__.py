from __future__ import annotations

from socksbox.exporters.base import BaseExporter, Exporter, CompositeExporter
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

DEFAULT_EXPORTERS = CompositeExporter([
    AllTxtExporter(),
    WorkingTxtExporter(),
    Top10TxtExporter(),
    GroupedExporter(),
    ConfigExporter(),
    SummaryExporter(),
    DiagnosticsExporter(),
])

__all__ = [
    "BaseExporter",
    "Exporter",
    "CompositeExporter",
    "AllTxtExporter",
    "WorkingTxtExporter",
    "Top10TxtExporter",
    "GroupedExporter",
    "ConfigExporter",
    "SummaryExporter",
    "DiagnosticsExporter",
    "DEFAULT_EXPORTERS",
]
