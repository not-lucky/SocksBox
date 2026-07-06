from __future__ import annotations

import sys
from typing import Any
from socksbox.runner.bridge import RunnerAbstraction, SingBoxEndpoint


class LoggingRunnerProxy:
    """Proxy pattern: wraps RunnerAbstraction to add logging."""

    def __init__(self, runner: RunnerAbstraction) -> None:
        self._runner = runner

    async def __aenter__(self) -> SingBoxEndpoint:
        print("[RunnerProxy] Starting sing-box runner...", file=sys.stderr)
        endpoint = await self._runner.__aenter__()
        print(f"[RunnerProxy] sing-box runner active at {endpoint.listen}:{endpoint.start_port}", file=sys.stderr)
        return endpoint

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: Any,
    ) -> None:
        print("[RunnerProxy] Stopping sing-box runner...", file=sys.stderr)
        await self._runner.__aexit__(exc_type, exc, tb)
        print("[RunnerProxy] sing-box runner stopped.", file=sys.stderr)
