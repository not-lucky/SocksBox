from __future__ import annotations

from abc import ABC, abstractmethod
from socksbox.pipeline.context import PipelineContext


class PipelineStage(ABC):
    """Chain of Responsibility: base pipeline execution stage handler."""

    def __init__(self) -> None:
        self._next_stage: PipelineStage | None = None

    def set_next(self, stage: PipelineStage) -> PipelineStage:
        self._next_stage = stage
        return stage

    async def handle(self, context: PipelineContext) -> PipelineContext:
        context = await self.process(context)
        if self._next_stage:
            return await self._next_stage.handle(context)
        return context

    @abstractmethod
    async def process(self, context: PipelineContext) -> PipelineContext:
        """Process the context and return the updated context."""
        ...
