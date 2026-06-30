from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiohttp
from aiohttp_socks import SocksConnector

from socksbox.config_gen import generate_singbox_config
from socksbox.models import ProxyInfo
from socksbox.runner import SubprocessSingBoxRunner


DEFAULT_DOWNLOAD_URL = (
    "https://speed.cloudflare.com/__down?bytes=1048576"
)


async def download_through_proxy(
    listen: str,
    socks_port: int,
    url: str,
    timeout: float,
    label: str,
) -> dict[str, Any]:
    """Download `url` through a single SOCKS5 proxy and measure throughput.

    Returns a dict with keys: status, bytes_downloaded, elapsed_s,
    speed_kbps, http_status, error_type, error, traceback.
    """
    record: dict[str, Any] = {
        "status": "failed",
        "url": url,
        "bytes_downloaded": 0,
        "elapsed_s": 0.0,
        "speed_kbps": 0.0,
        "http_status": None,
    }
    connector = SocksConnector.from_url(f"socks5://{listen}:{socks_port}")
    start = time.monotonic()
    try:
        timeout_obj = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 10.0))
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, timeout=timeout_obj, allow_redirects=True) as resp:
                record["http_status"] = resp.status
                if resp.status >= 400:
                    record.update({
                        "error_type": "HTTPError",
                        "error": f"non-2xx response: HTTP {resp.status}",
                    })
                    return record
                total = 0
                async for chunk in resp.content.iter_chunked(8192):
                    if chunk:
                        total += len(chunk)
        elapsed = max(time.monotonic() - start, 1e-6)
        speed_kbps = (total / elapsed) / 1024.0
        record.update({
            "status": "ok",
            "bytes_downloaded": total,
            "elapsed_s": round(elapsed, 3),
            "speed_kbps": round(speed_kbps, 1),
        })
        return record
    except Exception as exc:
        elapsed = max(time.monotonic() - start, 1e-6)
        record.update({
            "elapsed_s": round(elapsed, 3),
            "error_type": type(exc).__name__,
            "error": str(exc),
            "traceback": traceback.format_exc(),
        })
        print(f"  [download-fail] {label}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return record


async def run_download_verification(
    proxies: list[ProxyInfo],
    start_port: int,
    listen: str,
    sing_box: str,
    url: str = DEFAULT_DOWNLOAD_URL,
    timeout: float = 20.0,
    concurrency: int = 5,
    output_dir: Path | None = None,
    verbose: bool = False,
    demote_on_failure: bool = True,
) -> dict[str, Any]:
    """Concurrently download `url` through each working proxy.

    Starts a dedicated sing-box instance, runs the test with at most
    `concurrency` in-flight downloads (default 5, configurable), then stops
    sing-box. Writes a pass/fail report to `output_dir`. If
    `demote_on_failure` is True (default), proxies that fail the download
    have their `latency_ms` set to infinity so `proxy.working` is False and
    they are excluded from `working`-filtered exports.

    Returns the report dict (also containing `demoted_indices`).
    """
    working = [p for p in proxies if p.working]
    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "timeout_s": timeout,
        "concurrency": concurrency,
        "mode": "concurrent",
        "total_proxies": len(proxies),
        "tested_proxies": len(working),
        "passed": 0,
        "failed": 0,
        "success_rate": 0.0,
        "demoted": 0,
        "results": [],
        "errors": [],
    }

    if not working:
        print("No working proxies to download-test.", file=sys.stderr)
        if output_dir is not None:
            _write_report(report, output_dir)
        return report

    final_port = start_port + len(working) - 1
    if final_port > 65535:
        report["errors"].append({
            "stage": "setup",
            "error_type": "ValueError",
            "error": f"final port would be {final_port}; too many proxies",
        })
        if output_dir is not None:
            _write_report(report, output_dir)
        return report

    try:
        subprocess.run(
            [sing_box, "version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        report["errors"].append({
            "stage": "setup",
            "error_type": type(exc).__name__,
            "error": f"sing-box unavailable: {exc}",
        })
        print(f"[download-test] sing-box unavailable: {exc}", file=sys.stderr)
        if output_dir is not None:
            _write_report(report, output_dir)
        return report

    config = generate_singbox_config(working, start_port=start_port, listen=listen)
    runner = SubprocessSingBoxRunner(
        config,
        sing_box=sing_box,
        listen=listen,
        start_port=start_port,
        startup_delay=2.0,
    )

    try:
        async with runner as endpoint:
            print(
                f"Starting sing-box for download verification "
                f"({len(working)} proxies, concurrency={concurrency})...",
                file=sys.stderr,
            )

            sem = asyncio.Semaphore(max(1, concurrency))
            completed = 0
            total = len(working)

            async def worker(idx: int, proxy: ProxyInfo) -> tuple[int, dict[str, Any]]:
                nonlocal completed
                port = endpoint.start_port + idx
                label = " ".join(str(proxy.label).split())
                async with sem:
                    if verbose:
                        print(f"[download] {idx + 1}/{total} -> {label}", file=sys.stderr)
                    record = await download_through_proxy(
                        listen=endpoint.listen,
                        socks_port=port,
                        url=url,
                        timeout=timeout,
                        label=label,
                    )
                    completed += 1
                    print(
                        f"Download progress: {completed}/{total}...",
                        end="\r",
                        file=sys.stderr,
                    )
                    return idx, record

            tasks = [worker(idx, proxy) for idx, proxy in enumerate(working)]
            outcomes = await asyncio.gather(*tasks)
            print("", file=sys.stderr)

            for idx, record in outcomes:
                proxy = working[idx]
                port = endpoint.start_port + idx
                result = {
                    "index": idx + 1,
                    "socks_port": port,
                    "link": proxy.link,
                    "protocol": proxy.protocol,
                    "label": proxy.label,
                    "latency_ms": round(proxy.latency_ms, 1),
                    "country_code": proxy.country_code,
                    **record,
                }
                report["results"].append(result)
                diag = proxy.diagnostics.setdefault("download_test", {})
                diag.update({
                    "status": record["status"],
                    "url": url,
                    "bytes_downloaded": record["bytes_downloaded"],
                    "elapsed_s": record["elapsed_s"],
                    "speed_kbps": record["speed_kbps"],
                    "http_status": record["http_status"],
                })
                if record["status"] == "ok":
                    report["passed"] += 1
                    if verbose:
                        print(
                            f"  [ok] {proxy.label}: {record['speed_kbps']:.1f} KiB/s "
                            f"({record['bytes_downloaded']} bytes in {record['elapsed_s']:.2f}s)",
                            file=sys.stderr,
                        )
                else:
                    report["failed"] += 1
                    diag.update({
                        "error_type": record.get("error_type", "Unknown"),
                        "error": record.get("error", "unknown failure"),
                    })
                    report["errors"].append({
                        "stage": "download",
                        "proxy_index": idx + 1,
                        "socks_port": port,
                        "label": proxy.label,
                        "link": proxy.link,
                        "error_type": record.get("error_type", "Unknown"),
                        "error": record.get("error", "unknown failure"),
                        "traceback": record.get("traceback"),
                    })
                    if demote_on_failure:
                        proxy.latency_ms = float("inf")
                        report["demoted"] += 1
                        if verbose:
                            print(f"  [demote] {proxy.label}: marked not working", file=sys.stderr)

    except Exception as exc:
        report["errors"].append({
            "stage": "runner",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "traceback": traceback.format_exc(),
        })
        print(f"[download-test] runner failure: {exc}", file=sys.stderr)

    if report["tested_proxies"] > 0:
        report["success_rate"] = round(report["passed"] / report["tested_proxies"], 4)

    print(
        f"Download verification complete: {report['passed']}/{report['tested_proxies']} "
        f"passed (success rate {report['success_rate'] * 100:.1f}%).",
        file=sys.stderr,
    )
    if report.get("demoted"):
        print(
            f"Marked {report['demoted']} failed proxy(ies) as not working.",
            file=sys.stderr,
        )
    if report["errors"]:
        print(
            f"Captured {len(report['errors'])} download error(s) for debugging.",
            file=sys.stderr,
        )

    if output_dir is not None:
        _write_report(report, output_dir)

    return report


def _write_report(report: dict[str, Any], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "download_report.json"
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"Download report written to {path}", file=sys.stderr)
    return path


def print_pass_fail_summary(report: dict[str, Any]) -> None:
    """Print a clear pass/fail table to stderr."""
    results = report.get("results", [])
    if not results:
        return
    print("\nDownload verification (concurrent):", file=sys.stderr)
    print(
        f"  {'#':>3} {'STATUS':<6} {'SPEED':>12} {'BYTES':>10} "
        f"{'PROTOCOL':<10} {'LABEL'}",
        file=sys.stderr,
    )
    for r in results:
        status = "PASS" if r["status"] == "ok" else "FAIL"
        speed = f"{r['speed_kbps']:.1f} KiB/s" if r["status"] == "ok" else "-"
        bytes_disp = f"{r['bytes_downloaded']}" if r["status"] == "ok" else "-"
        label = " ".join(str(r["label"]).split())
        print(
            f"  {r['index']:>3} {status:<6} {speed:>12} {bytes_disp:>10} "
            f"{r['protocol']:<10} {label}",
            file=sys.stderr,
        )
    print(
        f"\n  Summary: {report['passed']} passed / {report['failed']} failed "
        f"(success rate {report['success_rate'] * 100:.1f}%)",
        file=sys.stderr,
    )
    if report.get("demoted"):
        print(
            f"  Marked {report['demoted']} failed proxy(ies) as not working.",
            file=sys.stderr,
        )