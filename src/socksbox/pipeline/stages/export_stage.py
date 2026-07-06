from __future__ import annotations

import sys
from pathlib import Path
from socksbox.pipeline.stage import PipelineStage
from socksbox.pipeline.context import PipelineContext
from socksbox.exporter import export_all
from socksbox.config_gen import generate_singbox_config


class ExportStage(PipelineStage):
    """Pipeline stage to export proxies to files using CompositeExporter."""

    async def process(self, context: PipelineContext) -> PipelineContext:
        output_dir = context.output_dir or Path(context.settings.get("output_dir", "output"))
        start_port = context.settings.get("start_port", 10808)
        listen = context.settings.get("listen", "127.0.0.1")

        working = [p for p in context.proxies if p.working]
        if not working:
            print("No working proxies. Skipping export.", file=sys.stderr)
            return context

        # Generate config for export
        config = generate_singbox_config(working, start_port=start_port, listen=listen)
        context.config = config

        export_all(
            context.proxies,
            config,
            output_dir,
            start_port=start_port,
            issues=context.issues,
        )

        return context
