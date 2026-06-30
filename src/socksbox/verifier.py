from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import time
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


async def test_socks5_latency(
    proxy_host: str,
    proxy_port: int,
    target_host: str = "cp.cloudflare.com",
    target_port: int = 80,
    timeout: float = 4.0,
) -> tuple[float | None, Exception | None]:
    writer = None
    try:
        start_time = time.monotonic()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port), timeout=timeout
        )
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        res = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if res != b"\x05\x00":
            return None, ValueError(f"SOCKS5 auth rejected, server returned: {res!r}")
        host_bytes = target_host.encode("ascii")
        req = bytearray([0x05, 0x01, 0x00, 0x03, len(host_bytes)]) + host_bytes + target_port.to_bytes(2, "big")
        writer.write(req)
        await writer.drain()
        resp_header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if resp_header[0] != 5:
            return None, ValueError(f"SOCKS5 invalid protocol version in reply: {resp_header[0]}")
        if resp_header[1] != 0:
            return None, ValueError(f"SOCKS5 connection failed (REP={resp_header[1]})")
        atyp = resp_header[3]
        if atyp == 1:
            await asyncio.wait_for(reader.readexactly(6), timeout=timeout)
        elif atyp == 3:
            len_byte = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
            await asyncio.wait_for(reader.readexactly(len_byte[0] + 2), timeout=timeout)
        elif atyp == 4:
            await asyncio.wait_for(reader.readexactly(18), timeout=timeout)
        else:
            return None, ValueError(f"SOCKS5 unknown ATYP: {atyp}")
        http_req = (
            f"GET /generate_204 HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            "User-Agent: sing-box-latency-tester\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(http_req)
        await writer.drain()
        resp_data = await asyncio.wait_for(reader.read(100), timeout=timeout)
        if not resp_data or b"HTTP/1." not in resp_data:
            return None, ValueError(f"Invalid target HTTP response: {resp_data!r}")
        latency = (time.monotonic() - start_time) * 1000
        return latency, None
    except Exception as exc:
        return None, exc
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


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
    latencies = []
    attempts: list[dict[str, Any]] = []
    last_error = None
    for attempt in range(1, tries + 1):
        lat, err = await test_socks5_latency(
            proxy_host, proxy_port, target_host=target_host, target_port=target_port, timeout=timeout
        )
        attempt_record: dict[str, Any] = {"attempt": attempt}
        if lat is not None:
            latencies.append(lat)
            attempt_record["status"] = "ok"
            attempt_record["latency_ms"] = round(lat, 1)
        else:
            attempt_record["status"] = "failed"
        if err is not None:
            last_error = err
            attempt_record["error_type"] = type(err).__name__
            attempt_record["error"] = str(err)
        attempts.append(attempt_record)
        await asyncio.sleep(delay)
    diagnostic: dict[str, Any] = {
        "status": "ok" if latencies else "failed",
        "tries": tries,
        "target_host": target_host,
        "target_port": target_port,
        "timeout": timeout,
        "attempts": attempts,
    }
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        diagnostic["latency_ms"] = round(avg_latency, 1)
        return avg_latency, diagnostic
    if verbose and last_error:
        print(f"[Debug] Port {proxy_port} failed: {type(last_error).__name__}: {last_error}", file=sys.stderr)
    if last_error:
        diagnostic["error_type"] = type(last_error).__name__
        diagnostic["error"] = str(last_error)
    return float("inf"), diagnostic


async def curl_ipinfo_forbidden_check(
    proxy_host: str,
    proxy_port: int,
    curl_bin: str = "curl",
    timeout: float = 10.0,
) -> tuple[bool, int | None]:
    """Run ``curl --socks5 <proxy_host>:<proxy_port> ipinfo.io/json`` and detect
    the 403 Forbidden block page that Google serves when the proxy's outbound
    IP has been flagged.

    Returns a tuple of ``(is_blocked, http_status)``. ``is_blocked`` is True
    only when the response carries the exact forbidden message markers and an
    HTTP status of 403. The check fires immediately on the first response —
    no retries are performed.
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
