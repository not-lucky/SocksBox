from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from socksbox.models import ProxyInfo
from socksbox.runner import SubprocessSingBoxRunner
from socksbox.status import (
    DEFAULT_AUDIT_LOG_NAME,
    IPINFO_FORBIDDEN_MARKER,
    IPINFO_FORBIDDEN_MARKER_PATH,
    IPINFO_FORBIDDEN_STATUS,
    _mark_proxy_not_working,
    _response_carries_forbidden,
    log_forbidden_detection,
)
from socksbox.verification import ProxyVerificationContext, Socks5LatencyStrategy


async def test_socks5_latency(
    proxy_host: str,
    proxy_port: int,
    target_host: str = "cp.cloudflare.com",
    target_port: int = 80,
    timeout: float = 4.0,
) -> tuple[float | None, Exception | None]:
    """Shorthand delegation to the Socks5LatencyStrategy for tests/compatibility."""
    strategy = Socks5LatencyStrategy()
    return await strategy.measure(proxy_host, proxy_port, target_host, target_port, timeout)


async def measure_proxy_average_latency(
    proxy_host: str,
    proxy_port: int,
    target_host: str = "cp.cloudflare.com",
    target_port: int = 80,
    tries: int = 5,
    delay: float = 0.1,
    timeout: float = 4.0,
    verbose: bool = False,
) -> tuple[float, dict[str, Any]]:
    """Shorthand delegation to ProxyVerificationContext and Socks5LatencyStrategy."""
    # Create a mock proxy to run the context on
    from socksbox.models import ProxyInfoBuilder
    p = ProxyInfoBuilder().build()
    ctx = ProxyVerificationContext(p)
    strategy = Socks5LatencyStrategy()
    await ctx.verify(proxy_host, proxy_port, strategy, tries, delay, timeout, verbose)
    diag = p.diagnostics.get("verify", {})
    return p.latency_ms, diag


async def curl_ipinfo_forbidden_check(
    proxy_host: str,
    proxy_port: int,
    curl_bin: str = "curl",
    timeout: float = 10.0,
) -> tuple[bool, int | None]:
    """Run ``curl --socks5 <proxy_host>:<proxy_port> ipinfo.io/json`` and detect
    the 403 Forbidden block page that Google serves when the proxy's outbound
    IP has been flagged.
    """
    cmd = [
        curl_bin,
        "--socks5", f"{proxy_host}:{proxy_port}",
        "-sS",
        "-w", "\n__HTTP_STATUS__:%{http_code}",
        "--max-time", str(max(1, int(timeout))),
        "ipinfo.io/json",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            return False, None
    except FileNotFoundError:
        print(f"[forbidden-check] curl not found at {curl_bin!r}; skipping.", file=sys.stderr)
        return False, None

    body = (stdout.decode("utf-8", errors="ignore") or "") + (stderr.decode("utf-8", errors="ignore") or "")
    status: int | None = None
    if "__HTTP_STATUS__:" in body:
        try:
            status_str = body.rsplit("__HTTP_STATUS__:", 1)[-1].strip().split()[0]
            status = int(status_str)
        except (ValueError, IndexError):
            status = None

    is_blocked = status == IPINFO_FORBIDDEN_STATUS and _response_carries_forbidden(body)
    return is_blocked, status


def _build_config_for_indices(
    proxies: list[ProxyInfo],
    indices: list[int],
    start_port: int,
    listen: str,
) -> dict[str, Any]:
    inbounds = []
    outbounds = []
    route_rules = []
    for seq, idx in enumerate(indices):
        listen_port = start_port + seq
        inbound_tag = f"socks-{seq:03d}"
        outbound_tag = f"proxy-{seq:03d}"
        inbounds.append({"type": "socks", "tag": inbound_tag, "listen": listen, "listen_port": listen_port})
        outbound = dict(proxies[idx].outbound)
        outbound["tag"] = outbound_tag
        outbounds.append(outbound)
        route_rules.append({"inbound": inbound_tag, "action": "route", "outbound": outbound_tag})
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": route_rules},
    }


async def verify_proxies(
    proxies: list[ProxyInfo],
    start_port: int = 10808,
    listen: str = "127.0.0.1",
    sing_box: str = "sing-box",
    tries: int = 5,
    timeout: float = 4.0,
    concurrency: int = 100,
    target_host: str = "cp.cloudflare.com",
    target_port: int = 80,
    verbose: bool = False,
    audit_log_path: Path | None = None,
) -> list[ProxyInfo]:
    if not proxies:
        return proxies

    final_port = start_port + len(proxies) - 1
    if final_port > 65535:
        print(f"Too many proxies: final port would be {final_port}.", file=sys.stderr)
        return proxies

    try:
        subprocess.run([sing_box, "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print(f"Could not find sing-box executable: {sing_box}", file=sys.stderr)
        return proxies

    temp_fd, temp_name = tempfile.mkstemp(suffix=".json", prefix="socksbox_verify_")
    temp_path = Path(temp_name)
    os.close(temp_fd)
    removed_indices: set[int] = set()

    for _ in range(len(proxies)):
        active = [i for i in range(len(proxies)) if i not in removed_indices]
        if not active:
            print("All proxies removed due to config errors.", file=sys.stderr)
            return proxies

        config = _build_config_for_indices(proxies, active, start_port, listen)
        temp_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        check = subprocess.run([sing_box, "check", "-c", str(temp_path)], capture_output=True, text=True)
        if check.returncode == 0:
            break

        match = re.search(r"outbound\[(\d+)\]", check.stderr)
        if not match:
            print("sing-box configuration check failed!", file=sys.stderr)
            print(check.stderr, file=sys.stderr)
            for idx in active:
                verify_diag = proxies[idx].diagnostics.setdefault("verify", {})
                verify_diag.update({
                    "status": "failed",
                    "reason": "sing-box configuration check failed",
                    "error": check.stderr.strip(),
                })
            temp_path.unlink(missing_ok=True)
            return proxies

        bad_seq = int(match.group(1))
        real_idx = active[bad_seq]
        reason = check.stderr.strip().splitlines()[-1] if check.stderr.strip() else "unknown error"
        print(f"  Removing [{real_idx}] {proxies[real_idx].label}: {reason}", file=sys.stderr)
        verify_diag = proxies[real_idx].diagnostics.setdefault("verify", {})
        verify_diag.update({
            "status": "failed",
            "reason": "sing-box configuration error",
            "outbound_index": bad_seq,
            "error": reason,
            "stderr": check.stderr.strip(),
        })
        removed_indices.add(real_idx)
    else:
        print("Too many config errors, giving up.", file=sys.stderr)
        temp_path.unlink(missing_ok=True)
        return proxies

    for i in removed_indices:
        proxies[i].latency_ms = float("inf")

    active = [i for i in range(len(proxies)) if i not in removed_indices]
    if not active:
        print("No testable proxies remaining.", file=sys.stderr)
        temp_path.unlink(missing_ok=True)
        return proxies

    if removed_indices:
        config = _build_config_for_indices(proxies, active, start_port, listen)
        temp_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Continuing with {len(active)}/{len(proxies)} proxies ({len(removed_indices)} incompatible removed).", file=sys.stderr)

    # Map: seq position in active config -> real proxy index
    port_map: dict[int, int] = {}  # seq -> real_idx
    for seq, idx in enumerate(active):
        port_map[seq] = idx

    config = _build_config_for_indices(proxies, active, start_port, listen)
    try:
        async with SubprocessSingBoxRunner(
            config,
            sing_box=sing_box,
            listen=listen,
            start_port=start_port,
            startup_delay=2.0,
        ) as runner:
            total = len(active)
            print(f"Testing {total} proxies (averaging {tries} tries per proxy)...", file=sys.stderr)

            sem = asyncio.Semaphore(concurrency)
            completed = 0

            async def worker(seq: int) -> tuple[int, float]:
                nonlocal completed
                async with sem:
                    avg_lat, diagnostic = await measure_proxy_average_latency(
                        runner.listen, runner.start_port + seq,
                        target_host=target_host, target_port=target_port,
                        tries=tries, timeout=timeout, verbose=verbose,
                    )
                    proxies[port_map[seq]].latency_ms = avg_lat
                    proxies[port_map[seq]].diagnostics["verify"] = diagnostic
                    completed += 1
                    print(f"Progress: {completed}/{total} processed...", end="\r", file=sys.stderr)
                    return port_map[seq], avg_lat

            tasks = [worker(seq) for seq in range(total)]
            results = await asyncio.gather(*tasks)
            print("", file=sys.stderr)

            # Assign latency results while sing-box is still alive.
            for real_idx, latency in results:
                proxies[real_idx].latency_ms = latency

            # Universal health gate: probe every working proxy with curl through
            # the local SOCKS5 endpoint. If the response carries the 403
            # Forbidden block page served for ipinfo.io/json, immediately flip
            # the proxy to "not working" and record an audit log entry.
            real_to_seq = {real_idx: seq for seq, real_idx in port_map.items()}
            working_real_indices = [
                real_idx for real_idx, lat in results if lat != float("inf")
            ]
            if working_real_indices:
                print(
                    f"Running ipinfo.io forbidden-response check on "
                    f"{len(working_real_indices)} working proxies...",
                    file=sys.stderr,
                )
                check_sem = asyncio.Semaphore(min(concurrency, 100))
                completed_checks = 0
                total_checks = len(working_real_indices)

                async def check_worker(real_idx: int):
                    nonlocal completed_checks
                    seq = real_to_seq[real_idx]
                    port = runner.start_port + seq
                    async with check_sem:
                        is_blocked, http_status = await curl_ipinfo_forbidden_check(
                            runner.listen, port, timeout=max(5.0, timeout + 2.0)
                        )
                    completed_checks += 1
                    print(
                        f"Forbidden check progress: {completed_checks}/{total_checks} processed...",
                        end="\r",
                        file=sys.stderr,
                    )
                    if is_blocked:
                        _mark_proxy_not_working(
                            proxies[real_idx],
                            reason="ipinfo.io forbidden 403 response",
                            extra={
                                "http_status": http_status,
                                "socks_port": port,
                                "check_command": (
                                    f"curl --socks5 {runner.listen}:{port} ipinfo.io/json"
                                ),
                            },
                        )
                        log_forbidden_detection(
                            proxies[real_idx],
                            socks_port=port,
                            audit_log_path=audit_log_path,
                            http_status=http_status,
                        )

                check_tasks = [check_worker(real_idx) for real_idx in working_real_indices]
                await asyncio.gather(*check_tasks)
                print("", file=sys.stderr)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return proxies
    finally:
        temp_path.unlink(missing_ok=True)

    proxies.sort(key=lambda p: p.latency_ms)
    return proxies
