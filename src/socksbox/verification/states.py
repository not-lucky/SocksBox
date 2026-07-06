from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any
from socksbox.models import ProxyInfo
from socksbox.verification.strategies import LatencyStrategy


class ProxyVerificationContext:
    """State pattern: Context that maintains the current verification state."""

    def __init__(self, proxy: ProxyInfo) -> None:
        self.proxy = proxy
        self.state: ProxyVerificationState = PendingState()

    def transition_to(self, state: ProxyVerificationState) -> None:
        self.state = state

    async def verify(
        self,
        host: str,
        port: int,
        strategy: LatencyStrategy,
        tries: int = 5,
        delay: float = 0.1,
        timeout: float = 4.0,
        verbose: bool = False,
    ) -> None:
        await self.state.verify(self, host, port, strategy, tries, delay, timeout, verbose)


class ProxyVerificationState(ABC):
    """State pattern: Base State class."""

    @abstractmethod
    async def verify(
        self,
        context: ProxyVerificationContext,
        host: str,
        port: int,
        strategy: LatencyStrategy,
        tries: int,
        delay: float,
        timeout: float,
        verbose: bool,
    ) -> None:
        ...


class PendingState(ProxyVerificationState):
    """Initial state of a proxy verification."""

    async def verify(
        self,
        context: ProxyVerificationContext,
        host: str,
        port: int,
        strategy: LatencyStrategy,
        tries: int,
        delay: float,
        timeout: float,
        verbose: bool,
    ) -> None:
        # Transition to TestingState to perform latency check
        context.transition_to(TestingState())
        await context.verify(host, port, strategy, tries, delay, timeout, verbose)


class TestingState(ProxyVerificationState):
    """State where attempts are being made to connect through the proxy."""

    async def verify(
        self,
        context: ProxyVerificationContext,
        host: str,
        port: int,
        strategy: LatencyStrategy,
        tries: int,
        delay: float,
        timeout: float,
        verbose: bool,
    ) -> None:
        latencies = []
        attempts: list[dict[str, Any]] = []
        last_error = None

        for attempt in range(1, tries + 1):
            lat, err = await strategy.measure(host, port, timeout=timeout)
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
            "timeout": timeout,
            "attempts": attempts,
        }

        if latencies:
            avg_latency = sum(latencies) / len(latencies)
            context.proxy.latency_ms = avg_latency
            diagnostic["latency_ms"] = round(avg_latency, 1)
            context.proxy.diagnostics["verify"] = diagnostic
            context.transition_to(WorkingState())
        else:
            context.proxy.latency_ms = float("inf")
            if last_error:
                diagnostic["error_type"] = type(last_error).__name__
                diagnostic["error"] = str(last_error)
            context.proxy.diagnostics["verify"] = diagnostic
            context.transition_to(FailedState())


class WorkingState(ProxyVerificationState):
    """State when the proxy is verified to be working."""

    async def verify(
        self,
        context: ProxyVerificationContext,
        host: str,
        port: int,
        strategy: LatencyStrategy,
        tries: int,
        delay: float,
        timeout: float,
        verbose: bool,
    ) -> None:
        pass  # Already verified and working


class FailedState(ProxyVerificationState):
    """State when the proxy is verified to be dead/failed."""

    async def verify(
        self,
        context: ProxyVerificationContext,
        host: str,
        port: int,
        strategy: LatencyStrategy,
        tries: int,
        delay: float,
        timeout: float,
        verbose: bool,
    ) -> None:
        pass  # Already failed


class BlockedState(ProxyVerificationState):
    """State when the proxy was working but is blocked (e.g. by ipinfo.io)."""

    async def verify(
        self,
        context: ProxyVerificationContext,
        host: str,
        port: int,
        strategy: LatencyStrategy,
        tries: int,
        delay: float,
        timeout: float,
        verbose: bool,
    ) -> None:
        pass
