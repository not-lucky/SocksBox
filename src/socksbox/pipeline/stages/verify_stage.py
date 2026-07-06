from __future__ import annotations

import sys
import traceback
from socksbox.pipeline.stage import PipelineStage
from socksbox.pipeline.context import PipelineContext
from socksbox.verifier import verify_proxies


class VerifyStage(PipelineStage):
    """Pipeline stage to run proxy latency verification using sing-box."""

    async def process(self, context: PipelineContext) -> PipelineContext:
        if not context.proxies:
            return context

        start_port = context.settings.get("start_port", 10808)
        listen = context.settings.get("listen", "127.0.0.1")
        sing_box = context.settings.get("sing_box", "sing-box")
        tries = context.settings.get("tries", 5)
        timeout = context.settings.get("timeout", 4.0)
        concurrency = context.settings.get("concurrency", 100)
        target_host = context.settings.get("target_host", "cp.cloudflare.com")
        target_port = context.settings.get("target_port", 80)
        verbose = context.settings.get("verbose", False)
        audit_log_path = context.settings.get("audit_log_path")

        try:
            context.proxies = await verify_proxies(
                context.proxies,
                start_port=start_port,
                listen=listen,
                sing_box=sing_box,
                tries=tries,
                timeout=timeout,
                concurrency=concurrency,
                target_host=target_host,
                target_port=target_port,
                verbose=verbose,
                audit_log_path=audit_log_path,
            )
        except Exception as exc:
            context.issues.append({
                "source": "all",
                "stage": "verify",
                "error": str(exc),
                "traceback": traceback.format_exc(),
            })
            print(f"[error] verify stage: {exc}", file=sys.stderr)

        return context
