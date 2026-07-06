from __future__ import annotations

import sys
import traceback
from socksbox.pipeline.stage import PipelineStage
from socksbox.pipeline.context import PipelineContext
from socksbox.sources import GLOBAL_SOURCE_FACTORY


class LoadStage(PipelineStage):
    """Pipeline stage to load proxies from all registered sources."""

    async def process(self, context: PipelineContext) -> PipelineContext:
        verify_ssl = not context.settings.get("no_verify_ssl", False)
        sources = GLOBAL_SOURCE_FACTORY.create_all_defaults()

        all_proxies = []
        parse_records = []
        issues = []

        for source in sources:
            source_url = getattr(source, "url", "unknown")
            prints_summary = getattr(source, "prints_summary", True)
            try:
                proxies, records = source.load(verify_ssl=verify_ssl)
            except Exception as exc:
                issues.append({
                    "source": source_url,
                    "stage": "load",
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                })
                if prints_summary:
                    print(f"[error] {source_url}: {exc}", file=sys.stderr)
                continue

            for record in records:
                enriched_record = dict(record)
                enriched_record.setdefault("source", source_url)
                parse_records.append(enriched_record)
                if enriched_record.get("status") == "failed":
                    issues.append(dict(enriched_record))

            if not proxies:
                issues.append({
                    "source": source_url,
                    "stage": "parse",
                    "status": "failed",
                    "kind": "empty_input",
                    "error": "no valid proxies found",
                })
                if prints_summary:
                    print(f"[skip] {source_url}: no valid proxies found", file=sys.stderr)
            else:
                if prints_summary:
                    print(f"[ok] {source_url}: {len(proxies)} proxies", file=sys.stderr)
                all_proxies.extend(proxies)

        context.proxies = all_proxies
        context.parse_records = parse_records
        context.issues = issues
        return context
