from __future__ import annotations

import json
import sys
from abc import ABC, abstractmethod
from collections import Counter
from pathlib import Path
from typing import Any, Dict

from socksbox.config_gen import generate_singbox_config
from socksbox.pipeline.context import PipelineContext
from socksbox.pipeline.mediator import PipelineMediator
from socksbox.pipeline.stages.load_stage import LoadStage
from socksbox.pipeline.stages.verify_stage import VerifyStage
from socksbox.pipeline.stages.enrich_stage import EnrichStage
from socksbox.pipeline.stages.export_stage import ExportStage
from socksbox.pipeline.stages.download_test_stage import DownloadTestStage


class PipelineCommand(ABC):
    """Command pattern: Base Command interface for pipeline actions."""

    def __init__(self, settings: Dict[str, Any]) -> None:
        self._settings = settings
        self._mediator = PipelineMediator()

    @abstractmethod
    async def execute(self) -> int:
        ...


class RunCommand(PipelineCommand):
    """Command to execute the full pipeline."""

    async def execute(self) -> int:
        context = PipelineContext(settings=self._settings)
        context = await self._mediator.run_full_pipeline(context)

        # Log errors to errors.json if there are issues
        combined = context.parse_records + context.issues
        if combined:
            output_dir = Path(self._settings.get("output_dir", "output"))
            output_dir.mkdir(parents=True, exist_ok=True)
            path = output_dir / "errors.json"
            path.write_text(json.dumps(combined, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"Logged {len(combined)} source error(s) to {path}", file=sys.stderr)

        if not context.proxies:
            print("No valid proxies from any source.", file=sys.stderr)
            return 1

        working = [p for p in context.proxies if p.working]
        if not working:
            print("No working proxies. Skipping enrichment and export.", file=sys.stderr)
            return 1

        return 0


class VerifyCommand(PipelineCommand):
    """Command to parse and verify proxies."""

    async def execute(self) -> int:
        context = PipelineContext(settings=self._settings)
        stages = [LoadStage(), VerifyStage()]
        context = await self._mediator.execute_chain(context, stages)

        if not context.proxies:
            print("No valid proxies from any source.", file=sys.stderr)
            return 1

        output_path = Path(self._settings.get("output", "sorted_links.txt"))
        working = [p for p in context.proxies if p.working]

        output_path.write_text(
            f"# Verified: {len(working)} working / {len(context.proxies)} total\n\n"
            + "".join(f"{p.link}\n" for p in working),
            encoding="utf-8",
        )

        print(f"Saved {len(working)} working proxies to {output_path}.", file=sys.stderr)
        if working:
            print("\nTop 10:", file=sys.stderr)
            for rank, p in enumerate(working[:10], 1):
                label = " ".join(str(p.label).split())
                print(f"  {rank:2d}. {p.latency_ms:6.1f}ms | {p.protocol:12s} | {label}", file=sys.stderr)

        return 0


class EnrichCommand(PipelineCommand):
    """Command to parse, verify, and enrich proxies."""

    async def execute(self) -> int:
        context = PipelineContext(settings=self._settings)
        stages = [LoadStage(), VerifyStage(), EnrichStage()]
        context = await self._mediator.execute_chain(context, stages)

        if not context.proxies:
            print("No valid proxies from any source.", file=sys.stderr)
            return 1

        working = [p for p in context.proxies if p.working]
        if not working:
            print("No working proxies to enrich.", file=sys.stderr)
            return 1

        print("\nEnriched working proxies:", file=sys.stderr)
        for p in working:
            cc = p.country_code or "?"
            print(f"  {p.latency_ms:6.1f}ms | {cc:2s} | {p.protocol:12s} | {p.label}")

        return 0


class ParseCommand(PipelineCommand):
    """Command to parse and display proxy info."""

    async def execute(self) -> int:
        context = PipelineContext(settings=self._settings)
        stages = [LoadStage()]
        context = await self._mediator.execute_chain(context, stages)

        if not context.proxies:
            print("No valid proxies from any source.", file=sys.stderr)
            return 1

        print(f"Total: {len(context.proxies)} proxies from 3 hardcoded source(s):\n")
        by_proto = Counter(p.protocol for p in context.proxies)
        for proto, count in by_proto.most_common():
            print(f"  {proto}: {count}")
        print(f"\nFirst 5:")
        for p in context.proxies[:5]:
            label = " ".join(str(p.label).split())
            print(f"  {p.protocol:12s} | {label}")

        return 0


class ConfigCommand(PipelineCommand):
    """Command to generate sing-box config without verification."""

    async def execute(self) -> int:
        context = PipelineContext(settings=self._settings)
        stages = [LoadStage()]
        context = await self._mediator.execute_chain(context, stages)

        if not context.proxies:
            print("No valid proxies from any source.", file=sys.stderr)
            return 1

        start_port = self._settings.get("start_port", 10808)
        listen = self._settings.get("listen", "127.0.0.1")
        legacy_route = self._settings.get("legacy_route", False)

        config = generate_singbox_config(context.proxies, start_port=start_port, listen=listen, legacy_route=legacy_route)

        output_path = Path(self._settings.get("output", "config.json"))
        output_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Created {output_path} with {len(context.proxies)} proxies.")

        return 0
