from __future__ import annotations

import sys
import traceback
from socksbox.pipeline.stage import PipelineStage
from socksbox.pipeline.context import PipelineContext
from socksbox.enricher import enrich_proxies


def parse_tokens(raw: str) -> list[str] | None:
    if not raw:
        return None
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    return tokens or None


class EnrichStage(PipelineStage):
    """Pipeline stage to enrich proxies with geo information using ipinfo.io."""

    async def process(self, context: PipelineContext) -> PipelineContext:
        if context.settings.get("no_enrich", False):
            return context

        working = [p for p in context.proxies if p.working]
        if not working:
            print("No working proxies. Skipping enrichment.", file=sys.stderr)
            return context

        start_port = context.settings.get("start_port", 10808)
        listen = context.settings.get("listen", "127.0.0.1")
        sing_box = context.settings.get("sing_box", "sing-box")
        concurrency = context.settings.get("concurrency", 100)
        ipinfo_token = context.settings.get("ipinfo_token", "")
        verbose = context.settings.get("verbose", False)
        audit_log_path = context.settings.get("audit_log_path")

        # Parse tokens
        tokens = None
        if ipinfo_token:
            tokens = [t.strip() for t in ipinfo_token.split(",") if t.strip()]

        try:
            # We must run with live sing-box endpoint!
            # Let's import the runner or live helper. Since cli.py has enrich_with_live_sing_box,
            # we can run it or use our new runner bridge directly!
            # Let's do it clean: use SubprocessSingBoxRunner context manager here.
            from socksbox.runner import SubprocessSingBoxRunner
            from socksbox.config_gen import generate_singbox_config

            config = generate_singbox_config(working, start_port=start_port, listen=listen)
            async with SubprocessSingBoxRunner(
                config,
                sing_box=sing_box,
                listen=listen,
                start_port=start_port,
                startup_delay=2.0,
            ) as endpoint:
                context.proxies = await enrich_proxies(
                    context.proxies,
                    start_port=endpoint.start_port,
                    listen=endpoint.listen,
                    concurrency=min(concurrency, 50),
                    tokens=tokens,
                    verbose=verbose,
                    audit_log_path=audit_log_path,
                )
        except Exception as exc:
            context.issues.append({
                "source": "all",
                "stage": "enrich",
                "error": str(exc),
                "traceback": traceback.format_exc(),
            })
            print(f"[error] enrich stage: {exc}", file=sys.stderr)

        return context
