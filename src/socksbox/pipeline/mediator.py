from __future__ import annotations

from typing import List
from socksbox.pipeline.context import PipelineContext
from socksbox.pipeline.stage import PipelineStage
from socksbox.pipeline.stages.load_stage import LoadStage
from socksbox.pipeline.stages.verify_stage import VerifyStage
from socksbox.pipeline.stages.enrich_stage import EnrichStage
from socksbox.pipeline.stages.export_stage import ExportStage
from socksbox.pipeline.stages.download_test_stage import DownloadTestStage


class PipelineMediator:
    """Mediator pattern: Coordinates actions between different pipeline stages.
    Facade pattern: Provides a simplified high-level interface to execute pipelines.
    """

    def __init__(self) -> None:
        pass

    async def execute_chain(self, context: PipelineContext, stages: List[PipelineStage]) -> PipelineContext:
        """Connects the list of stages in a Chain of Responsibility and executes it."""
        if not stages:
            return context
        for i in range(len(stages) - 1):
            stages[i].set_next(stages[i + 1])
        return await stages[0].handle(context)

    async def run_full_pipeline(self, context: PipelineContext) -> PipelineContext:
        """Facade method to run the entire parse, verify, enrich, export, download test pipeline."""
        stages = [
            LoadStage(),
            VerifyStage(),
            EnrichStage(),
            ExportStage(),
            DownloadTestStage(),
        ]
        return await self.execute_chain(context, stages)
