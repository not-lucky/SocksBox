from __future__ import annotations

import asyncio
import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class LatencyStrategy(Protocol):
    """Strategy pattern: interface for measuring proxy latency."""

    async def measure(
        self,
        proxy_host: str,
        proxy_port: int,
        target_host: str,
        target_port: int,
        timeout: float,
    ) -> tuple[float | None, Exception | None]:
        ...


class Socks5LatencyStrategy:
    """Concrete strategy to measure SOCKS5 latency using SOCKS5 handshake."""

    async def measure(
        self,
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
