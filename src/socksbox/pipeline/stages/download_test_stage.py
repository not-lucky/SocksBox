from __future__ import annotations

import sys
import traceback
from pathlib import Path
from socksbox.pipeline.stage import PipelineStage
from socksbox.pipeline.context import PipelineContext
from socksbox.downloader import run_download_verification, print_pass_fail_summary
from socksbox.exporter import export_all
from socksbox.config_gen import generate_singbox_config


class DownloadTestStage(PipelineStage):
    """Pipeline stage to run concurrent download verification on working proxies."""

    async def process(self, context: PipelineContext) -> PipelineContext:
        if not context.settings.get("download_test", False):
            return context

        working = [p for p in context.proxies if p.working]
        if not working:
            print("No working proxies for download test.", file=sys.stderr)
            return context

        output_dir = context.output_dir or Path(context.settings.get("output_dir", "output"))
        start_port = context.settings.get("start_port", 10808)
        listen = context.settings.get("listen", "127.0.0.1")
        sing_box = context.settings.get("sing_box", "sing-box")
        download_url = context.settings.get("download_url", "https://speed.cloudflare.com/__down?bytes=1048576")
        download_timeout = context.settings.get("download_timeout", 30.0)
        download_concurrency = context.settings.get("download_concurrency", 5)
        verbose = context.settings.get("verbose", False)

        print("\n=== Concurrent download verification ===", file=sys.stderr)
        try:
            download_report = await run_download_verification(
                context.proxies,
                start_port=start_port,
                listen=listen,
                sing_box=sing_box,
                url=download_url,
                timeout=download_timeout,
                concurrency=max(1, download_concurrency),
                output_dir=output_dir,
                verbose=verbose,
            )
        except Exception as exc:
            context.issues.append({
                "source": "all",
                "stage": "download_test",
                "error": str(exc),
                "traceback": traceback.format_exc(),
            })
            print(f"[error] download_test stage: {exc}", file=sys.stderr)
            return context

        print_pass_fail_summary(download_report)

        for err in download_report.get("errors", []):
            context.issues.append({
                "source": "download_test",
                "stage": err.get("stage", "download"),
                "kind": err.get("error_type"),
                "label": err.get("label"),
                "socks_port": err.get("socks_port"),
                "error": err.get("error"),
                "traceback": err.get("traceback"),
            })

        if download_report.get("demoted"):
            final_working = [p for p in context.proxies if p.working]
            final_failed = [p for p in context.proxies if not p.working]
            print(
                f"Re-exporting after demotion: {len(final_working)} working / "
                f"{len(final_failed)} failed.",
                file=sys.stderr,
            )
            config = generate_singbox_config(final_working, start_port=start_port, listen=listen)
            context.config = config
            export_all(context.proxies, config, output_dir, start_port=start_port, issues=context.issues)

        return context
