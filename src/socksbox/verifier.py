from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from socksbox.models import ProxyInfo

# Markers from Google's 403 Forbidden block page served when an IP has been
# flagged. The exact substring must appear in the curl response body for the
# proxy to be considered "not working" by the validation check.
IPINFO_FORBIDDEN_MARKER = "Your client does not have permission to get URL"
IPINFO_FORBIDDEN_MARKER_PATH = "<code>/json</code>"
IPINFO_FORBIDDEN_STATUS = 403
DEFAULT_AUDIT_LOG_NAME = "forbidden_detections.log"


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


def curl_ipinfo_forbidden_check(
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
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 2
        )
    except FileNotFoundError:
        print(f"[forbidden-check] curl not found at {curl_bin!r}; skipping.", file=sys.stderr)
        return False, None
    except subprocess.TimeoutExpired:
        return False, None

    body = (result.stdout or "") + (result.stderr or "")
    status: int | None = None
    if "__HTTP_STATUS__:" in body:
        try:
            status_str = body.rsplit("__HTTP_STATUS__:", 1)[-1].strip().split()[0]
            status = int(status_str)
        except (ValueError, IndexError):
            status = None

    is_blocked = (
        status == IPINFO_FORBIDDEN_STATUS
        and IPINFO_FORBIDDEN_MARKER in body
        and IPINFO_FORBIDDEN_MARKER_PATH in body
    )
    return is_blocked, status


def _mark_proxy_not_working(
    proxy: ProxyInfo,
    reason: str,
    extra: dict[str, Any] | None = None,
) -> None:
    """Flip a proxy's status to not working and record diagnostics."""
    proxy.latency_ms = float("inf")
    forbidden_diag = proxy.diagnostics.setdefault("forbidden_check", {})
    record: dict[str, Any] = {
        "status": "not_working",
        "reason": reason,
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        record.update(extra)
    forbidden_diag.update(record)


def log_forbidden_detection(
    proxy: ProxyInfo,
    socks_port: int,
    audit_log_path: Path | None = None,
    http_status: int | None = None,
) -> None:
    """Emit an audit log entry for a forbidden-response detection.

    The entry always includes the proxy's IP (resolved via the proxy when
    available, falling back to its label/link), the local SOCKS5 port that
    was probed, and an ISO-8601 UTC timestamp. When ``audit_log_path`` is
    provided, the entry is also appended to that file for persistent
    auditing.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    proxy_ip = proxy.ip or proxy.label or proxy.link
    message = (
        f"[{timestamp}] proxy_marked_not_working "
        f"reason=ipinfo_forbidden_403 "
        f"http_status={http_status if http_status is not None else 'unknown'} "
        f"socks_port={socks_port} "
        f"proxy_ip={proxy_ip}"
    )
    print(message, file=sys.stderr)
    if audit_log_path is not None:
        audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        with audit_log_path.open("a", encoding="utf-8") as f:
            f.write(message + "\n")


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

    proc = None
    try:
        print("Starting sing-box testing instance...", file=sys.stderr)
        proc = subprocess.Popen(
            [sing_box, "run", "-c", str(temp_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        await asyncio.sleep(2.0)
        if proc.poll() is not None:
            print("Error: sing-box terminated early.", file=sys.stderr)
            return proxies

        total = len(active)
        print(f"Testing {total} proxies (averaging {tries} tries per proxy)...", file=sys.stderr)

        sem = asyncio.Semaphore(concurrency)
        completed = 0

        async def worker(seq: int) -> tuple[int, float]:
            nonlocal completed
            async with sem:
                avg_lat, diagnostic = await measure_proxy_average_latency(
                    listen, start_port + seq,
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
            for real_idx in working_real_indices:
                seq = real_to_seq[real_idx]
                port = start_port + seq
                is_blocked, http_status = curl_ipinfo_forbidden_check(
                    listen, port, timeout=max(5.0, timeout + 2.0)
                )
                if is_blocked:
                    _mark_proxy_not_working(
                        proxies[real_idx],
                        reason="ipinfo.io forbidden 403 response",
                        extra={
                            "http_status": http_status,
                            "socks_port": port,
                            "check_command": (
                                f"curl --socks5 {listen}:{port} ipinfo.io/json"
                            ),
                        },
                    )
                    log_forbidden_detection(
                        proxies[real_idx],
                        socks_port=port,
                        audit_log_path=audit_log_path,
                        http_status=http_status,
                    )

    finally:
        if proc is not None:
            print("Stopping sing-box testing instance...", file=sys.stderr)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        temp_path.unlink(missing_ok=True)

    proxies.sort(key=lambda p: p.latency_ms)
    return proxies
