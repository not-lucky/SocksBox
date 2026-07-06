from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from socksbox.config import AppConfig
from socksbox.status import DEFAULT_AUDIT_LOG_NAME
from socksbox.models import ProxyInfo
from socksbox.runner import SubprocessSingBoxRunner
from socksbox.enricher import enrich_proxies
from socksbox.config_gen import generate_singbox_config
from socksbox.pipeline import (
    ConfigCommand,
    EnrichCommand,
    ParseCommand,
    RunCommand,
    VerifyCommand,
)


async def enrich_with_live_sing_box(
    proxies: list[ProxyInfo],
    start_port: int,
    listen: str,
    sing_box: str,
    concurrency: int,
    tokens: list[str] | None,
    verbose: bool,
    audit_log_path: Path | None = None,
) -> list[ProxyInfo]:
    working = [p for p in proxies if p.working]
    if not working:
        return proxies

    config = generate_singbox_config(working, start_port=start_port, listen=listen)
    async with SubprocessSingBoxRunner(
        config,
        sing_box=sing_box,
        listen=listen,
        start_port=start_port,
        startup_delay=2.0,
    ) as endpoint:
        return await enrich_proxies(
            proxies,
            start_port=endpoint.start_port,
            listen=endpoint.listen,
            concurrency=concurrency,
            tokens=tokens,
            verbose=verbose,
            audit_log_path=audit_log_path,
        )


import traceback
from socksbox.sources import DEFAULT_SOURCES


def load_sources(verify_ssl: bool = True) -> tuple[list[ProxyInfo], list[dict], list[dict]]:
    if not verify_ssl:
        print("Warning: SSL certificate verification is disabled. This is insecure and should only be used for testing.", file=sys.stderr)
    all_proxies: list[ProxyInfo] = []
    parse_records: list[dict] = []
    issues: list[dict] = []

    for source in DEFAULT_SOURCES:
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

    return all_proxies, parse_records, issues


def parse_tokens(raw: str) -> list[str] | None:
    if not raw:
        return None
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    return tokens or None


def resolve_audit_log_path(audit_log: str | None, output_dir: Path | None) -> Path | None:
    """Resolve where the forbidden-detection audit log should be written."""
    if audit_log is not None:
        if not audit_log.strip():
            return None
        return Path(audit_log)
    base = output_dir if output_dir is not None else Path(".")
    return base / DEFAULT_AUDIT_LOG_NAME


async def cmd_run(args: argparse.Namespace) -> int:
    settings = vars(args)
    settings["audit_log_path"] = resolve_audit_log_path(args.audit_log, Path(args.output_dir))
    # Update global singleton configuration
    AppConfig.instance().update_from_dict(settings)
    command = RunCommand(settings)
    return await command.execute()


async def cmd_verify(args: argparse.Namespace) -> int:
    settings = vars(args)
    output_path = Path(args.output)
    settings["audit_log_path"] = resolve_audit_log_path(
        args.audit_log, output_path.parent if output_path.parent else Path(".")
    )
    # Update global singleton configuration
    AppConfig.instance().update_from_dict(settings)
    command = VerifyCommand(settings)
    return await command.execute()


async def cmd_enrich(args: argparse.Namespace) -> int:
    settings = vars(args)
    settings["audit_log_path"] = resolve_audit_log_path(args.audit_log, Path("."))
    # Update global singleton configuration
    AppConfig.instance().update_from_dict(settings)
    command = EnrichCommand(settings)
    return await command.execute()


def cmd_parse(args: argparse.Namespace) -> int:
    settings = vars(args)
    # Update global singleton configuration
    AppConfig.instance().update_from_dict(settings)
    command = ParseCommand(settings)
    return asyncio.run(command.execute())


def cmd_config(args: argparse.Namespace) -> int:
    settings = vars(args)
    # Update global singleton configuration
    AppConfig.instance().update_from_dict(settings)
    command = ConfigCommand(settings)
    return asyncio.run(command.execute())


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--start-port", type=int, default=10808, help="First SOCKS port (default: 10808)")
    parser.add_argument("--listen", default="127.0.0.1", help="Listen address (default: 127.0.0.1)")
    parser.add_argument("--concurrency", type=int, default=100, help="Max concurrent operations (default: 100)")
    parser.add_argument("--tries", type=int, default=5, help="Latency test attempts per proxy (default: 5)")
    parser.add_argument("--timeout", type=float, default=4.0, help="Timeout per attempt in seconds (default: 4.0)")
    parser.add_argument("--target-host", default="cp.cloudflare.com", help="Latency test target host")
    parser.add_argument("--target-port", type=int, default=80, help="Latency test target port")
    parser.add_argument("--sing-box", default="sing-box", help="Path to sing-box binary")
    parser.add_argument("--ipinfo-token", default=os.environ.get("IPINFO_TOKEN", ""), help="ipinfo.io API token(s), comma-separated to cycle through multiple (or set IPINFO_TOKEN env var)")
    parser.add_argument("--no-enrich", action="store_true", help="Skip geo enrichment step")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification (INSECURE, use only for testing)")
    parser.add_argument(
        "--audit-log", default=None,
        help=(
            "Path to the audit log that records every ipinfo.io 403 Forbidden "
            "detection (proxy IP, SOCKS port, timestamp). Defaults to "
            "<output_dir>/forbidden_detections.log. Pass an empty string to disable."
        ),
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")


def main() -> int:
    parser = argparse.ArgumentParser(description="SocksBox: proxy toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_run = subparsers.add_parser("run", help="Full pipeline: parse, verify, enrich, export")
    add_common_args(p_run)
    p_run.add_argument("--output-dir", default="output", help="Output directory (default: output/)")
    p_run.add_argument("--download-test", action="store_true",
                       help="Run an opt-in, concurrent download verification after export to validate working proxies (off by default to keep the pipeline non-intrusive)")
    p_run.add_argument("--download-url", default="https://speed.cloudflare.com/__down?bytes=1048576",
                       help="Test URL used for the download verification (default: 1 MiB from Cloudflare)")
    p_run.add_argument("--download-timeout", type=float, default=30.0,
                       help="Per-proxy timeout in seconds for the download verification (default: 30)")
    p_run.add_argument("--download-concurrency", type=int, default=5,
                       help="Max in-flight download verifications (default: 5). Failed proxies are marked not working and excluded from exports.")

    p_verify = subparsers.add_parser("verify", help="Parse and verify proxies")
    add_common_args(p_verify)
    p_verify.add_argument("-o", "--output", default="sorted_links.txt", help="Output file")

    p_enrich = subparsers.add_parser("enrich", help="Parse, verify, and enrich with geo info")
    add_common_args(p_enrich)

    p_parse = subparsers.add_parser("parse", help="Parse and display proxy info")
    p_parse.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification (INSECURE, use only for testing)")

    p_config = subparsers.add_parser("config", help="Generate sing-box config (no verification)")
    p_config.add_argument("-o", "--output", default="config.json", help="Output config file")
    p_config.add_argument("--start-port", type=int, default=10808)
    p_config.add_argument("--listen", default="127.0.0.1")
    p_config.add_argument("--legacy-route", action="store_true")
    p_config.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification (INSECURE, use only for testing)")

    args = parser.parse_args()

    if args.command == "parse":
        return cmd_parse(args)
    if args.command == "config":
        return cmd_config(args)
    if args.command == "verify":
        return asyncio.run(cmd_verify(args))
    if args.command == "enrich":
        return asyncio.run(cmd_enrich(args))
    if args.command == "run":
        return asyncio.run(cmd_run(args))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
