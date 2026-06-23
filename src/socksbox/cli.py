from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import traceback
from datetime import datetime, timezone
from pathlib import Path

from socksbox.config_gen import generate_singbox_config
from socksbox.enricher import enrich_proxies
from socksbox.exporter import export_all
from socksbox.models import ProxyInfo
from socksbox.parser import load_and_parse
from socksbox.verifier import verify_proxies

DEFAULT_INPUT = "https://github.com/ebrasha/free-v2ray-public-list/raw/refs/heads/main/V2Ray-Config-By-EbraSha.txt"


def parse_tokens(raw: str) -> list[str] | None:
    if not raw:
        return None
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    return tokens or None


async def enrich_with_live_sing_box(
    proxies: list[ProxyInfo],
    start_port: int,
    listen: str,
    sing_box: str,
    concurrency: int,
    tokens: list[str] | None,
    verbose: bool,
) -> list[ProxyInfo]:
    working = [p for p in proxies if p.working]
    if not working:
        return proxies

    temp_fd, temp_name = tempfile.mkstemp(suffix=".json", prefix="socksbox_enrich_")
    temp_path = Path(temp_name)
    os.close(temp_fd)
    config = generate_singbox_config(working, start_port=start_port, listen=listen)
    temp_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    proc = subprocess.Popen(
        [sing_box, "run", "-c", str(temp_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        await asyncio.sleep(2.0)
        if proc.poll() is not None:
            raise RuntimeError("Error: sing-box terminated early.")

        return await enrich_proxies(
            proxies,
            start_port=start_port,
            listen=listen,
            concurrency=concurrency,
            tokens=tokens,
            verbose=verbose,
        )
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        temp_path.unlink(missing_ok=True)


def write_errors(errors: list[dict], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "errors.json"
    path.write_text(json.dumps(errors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Logged {len(errors)} source error(s) to {path}", file=sys.stderr)
    return path


def _dump_errors(parse_records: list[dict], issues: list[dict], output_dir: Path) -> None:
    combined = parse_records + issues
    if combined:
        write_errors(combined, output_dir)


def load_sources(sources: list[str], verify_ssl: bool = True) -> tuple[list[ProxyInfo], list[dict], list[dict]]:
    if not verify_ssl:
        print("Warning: SSL certificate verification is disabled. This is insecure and should only be used for testing.", file=sys.stderr)
    all_proxies: list[ProxyInfo] = []
    parse_records: list[dict] = []
    issues: list[dict] = []
    for source in sources:
        try:
            proxies, records = load_and_parse(source, verify_ssl=verify_ssl)
            for record in records:
                enriched_record = dict(record)
                enriched_record.setdefault("source", source)
                parse_records.append(enriched_record)
                if enriched_record.get("status") == "failed":
                    issues.append(dict(enriched_record))
            if not proxies:
                issues.append({"source": source, "stage": "parse", "status": "failed", "kind": "empty_input", "error": "no valid proxies found"})
                print(f"[skip] {source}: no valid proxies found", file=sys.stderr)
                continue
            print(f"[ok] {source}: {len(proxies)} proxies", file=sys.stderr)
            all_proxies.extend(proxies)
        except Exception as exc:
            issues.append({"source": source, "stage": "load", "error": str(exc),
                           "traceback": traceback.format_exc()})
            print(f"[error] {source}: {exc}", file=sys.stderr)
    return all_proxies, parse_records, issues


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("inputs", nargs="*", default=[DEFAULT_INPUT],
                        help="Input sources: file paths, URLs, or '-' for stdin (multiple allowed)")
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
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")


async def cmd_run(args: argparse.Namespace) -> int:
    proxies, parse_records, issues = load_sources(args.inputs, verify_ssl=not args.no_verify_ssl)
    if not proxies:
        _dump_errors(parse_records, issues, Path(args.output_dir))
        print("No valid proxies from any source.", file=sys.stderr)
        return 1

    print(f"Total: {len(proxies)} proxies from {len(args.inputs)} source(s).", file=sys.stderr)

    try:
        proxies = await verify_proxies(
            proxies, start_port=args.start_port, listen=args.listen, sing_box=args.sing_box,
            tries=args.tries, timeout=args.timeout, concurrency=args.concurrency,
            target_host=args.target_host, target_port=args.target_port, verbose=args.verbose,
        )
    except Exception as exc:
        issues.append({"source": "all", "stage": "verify", "error": str(exc),
                        "traceback": traceback.format_exc()})
        print(f"[error] verify stage: {exc}", file=sys.stderr)

    working = [p for p in proxies if p.working]
    print(f"Verification complete: {len(working)}/{len(proxies)} working.", file=sys.stderr)

    if not working:
        print("No working proxies. Skipping enrichment and export.", file=sys.stderr)
        _dump_errors(parse_records, issues, Path(args.output_dir))
        return 1

    if not args.no_enrich:
        try:
            proxies = await enrich_with_live_sing_box(
                proxies,
                start_port=args.start_port,
                listen=args.listen,
                sing_box=args.sing_box,
                concurrency=min(args.concurrency, 50),
                tokens=parse_tokens(args.ipinfo_token),
                verbose=args.verbose,
            )
        except Exception as exc:
            issues.append({"source": "all", "stage": "enrich", "error": str(exc),
                            "traceback": traceback.format_exc()})
            print(f"[error] enrich stage: {exc}", file=sys.stderr)

    config = generate_singbox_config(working, start_port=args.start_port, listen=args.listen)
    output_dir = Path(args.output_dir)
    export_all(proxies, config, output_dir, start_port=args.start_port, issues=issues)

    _dump_errors(parse_records, issues, output_dir)
    return 0


async def cmd_verify(args: argparse.Namespace) -> int:
    proxies, parse_records, issues = load_sources(args.inputs, verify_ssl=not args.no_verify_ssl)
    if not proxies:
        _dump_errors(parse_records, issues, Path("."))
        print("No valid proxies from any source.", file=sys.stderr)
        return 1

    print(f"Total: {len(proxies)} proxies from {len(args.inputs)} source(s).", file=sys.stderr)

    proxies = await verify_proxies(
        proxies, start_port=args.start_port, listen=args.listen, sing_box=args.sing_box,
        tries=args.tries, timeout=args.timeout, concurrency=args.concurrency,
        target_host=args.target_host, target_port=args.target_port, verbose=args.verbose,
    )

    working = [p for p in proxies if p.working]
    output_path = Path(args.output)
    with output_path.open("w", encoding="utf-8") as f:
        f.write(f"# Verified: {len(working)} working / {len(proxies)} total\n\n")
        for p in working:
            f.write(f"{p.link}\n")

    print(f"Saved {len(working)} working proxies to {output_path}.", file=sys.stderr)
    if working:
        print("\nTop 10:", file=sys.stderr)
        for rank, p in enumerate(working[:10], 1):
            label = " ".join(str(p.label).split())
            print(f"  {rank:2d}. {p.latency_ms:6.1f}ms | {p.protocol:12s} | {label}", file=sys.stderr)

    _dump_errors(parse_records, issues, output_path.parent or Path("."))
    return 0


async def cmd_enrich(args: argparse.Namespace) -> int:
    proxies, parse_records, issues = load_sources(args.inputs, verify_ssl=not args.no_verify_ssl)
    if not proxies:
        _dump_errors(parse_records, issues, Path("."))
        print("No valid proxies from any source.", file=sys.stderr)
        return 1

    print(f"Total: {len(proxies)} proxies from {len(args.inputs)} source(s).", file=sys.stderr)

    proxies = await verify_proxies(
        proxies, start_port=args.start_port, listen=args.listen, sing_box=args.sing_box,
        tries=args.tries, timeout=args.timeout, concurrency=args.concurrency,
        target_host=args.target_host, target_port=args.target_port, verbose=args.verbose,
    )

    working = [p for p in proxies if p.working]
    if not working:
        print("No working proxies to enrich.", file=sys.stderr)
        _dump_errors(parse_records, issues, Path("."))
        return 1

    proxies = await enrich_with_live_sing_box(
        proxies,
        start_port=args.start_port,
        listen=args.listen,
        sing_box=args.sing_box,
        concurrency=min(args.concurrency, 50),
        tokens=parse_tokens(args.ipinfo_token),
        verbose=args.verbose,
    )

    for p in working:
        cc = p.country_code or "?"
        print(f"  {p.latency_ms:6.1f}ms | {cc:2s} | {p.protocol:12s} | {p.label}")

    _dump_errors(parse_records, issues, Path("."))
    return 0


def cmd_parse(args: argparse.Namespace) -> int:
    proxies, parse_records, issues = load_sources(args.inputs, verify_ssl=not args.no_verify_ssl)
    if not proxies:
        _dump_errors(parse_records, issues, Path("."))
        print("No valid proxies from any source.", file=sys.stderr)
        return 1

    print(f"Total: {len(proxies)} proxies from {len(args.inputs)} source(s):\n")
    from collections import Counter
    by_proto = Counter(p.protocol for p in proxies)
    for proto, count in by_proto.most_common():
        print(f"  {proto}: {count}")
    print(f"\nFirst 5:")
    for p in proxies[:5]:
        label = " ".join(str(p.label).split())
        print(f"  {p.protocol:12s} | {label}")

    _dump_errors(parse_records, issues, Path("."))
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    proxies, parse_records, issues = load_sources(args.inputs, verify_ssl=not args.no_verify_ssl)
    if not proxies:
        _dump_errors(parse_records, issues, Path("."))
        print("No valid proxies from any source.", file=sys.stderr)
        return 1

    config = generate_singbox_config(proxies, start_port=args.start_port, listen=args.listen, legacy_route=args.legacy_route)

    output_path = Path(args.output)
    output_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Created {output_path} with {len(proxies)} proxies.")

    _dump_errors(parse_records, issues, output_path.parent or Path("."))
    return 0


def main():
    parser = argparse.ArgumentParser(description="SocksBox: proxy toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_run = subparsers.add_parser("run", help="Full pipeline: parse, verify, enrich, export")
    add_common_args(p_run)
    p_run.add_argument("--output-dir", default="output", help="Output directory (default: output/)")

    p_verify = subparsers.add_parser("verify", help="Parse and verify proxies")
    add_common_args(p_verify)
    p_verify.add_argument("-o", "--output", default="sorted_links.txt", help="Output file")

    p_enrich = subparsers.add_parser("enrich", help="Parse, verify, and enrich with geo info")
    add_common_args(p_enrich)

    p_parse = subparsers.add_parser("parse", help="Parse and display proxy info")
    p_parse.add_argument("inputs", nargs="*", default=["-"], help="Input sources (multiple allowed)")
    p_parse.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification (INSECURE, use only for testing)")

    p_config = subparsers.add_parser("config", help="Generate sing-box config (no verification)")
    p_config.add_argument("inputs", nargs="*", default=["-"], help="Input sources (multiple allowed)")
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


if __name__ == "__main__":
    raise SystemExit(main())
