from __future__ import annotations

import asyncio
import json
import os
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SingBoxEndpoint:
    """Addressing information for a running sing-box SOCKS endpoint."""

    listen: str
    start_port: int


class RunnerImplementation(ABC):
    """Bridge Pattern - Implementation Interface."""

    @abstractmethod
    async def start(self) -> SingBoxEndpoint:
        ...

    @abstractmethod
    async def stop(self) -> None:
        ...


class SubprocessImplementation(RunnerImplementation):
    """Bridge Pattern - Concrete Implementation managing a real sing-box subprocess."""

    def __init__(
        self,
        config: dict[str, Any],
        sing_box: str = "sing-box",
        listen: str = "127.0.0.1",
        start_port: int = 10808,
        startup_delay: float = 2.0,
    ) -> None:
        self.config = config
        self.sing_box = sing_box
        self.listen = listen
        self.start_port = start_port
        self.startup_delay = startup_delay
        self._proc: subprocess.Popen | None = None
        self._temp_path: Path | None = None

    async def start(self) -> SingBoxEndpoint:
        fd, name = tempfile.mkstemp(suffix=".json", prefix="socksbox_runner_")
        self._temp_path = Path(name)
        os.close(fd)
        self._temp_path.write_text(
            json.dumps(self.config, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        try:
            self._proc = subprocess.Popen(
                [self.sing_box, "run", "-c", str(self._temp_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except BaseException:
            self._cleanup()
            raise

        await asyncio.sleep(self.startup_delay)

        if self._proc.poll() is not None:
            returncode = self._proc.returncode
            self._cleanup()
            raise RuntimeError(
                f"sing-box terminated early during startup (return code {returncode})"
            )

        return SingBoxEndpoint(listen=self.listen, start_port=self.start_port)

    async def stop(self) -> None:
        self._cleanup()

    def _cleanup(self) -> None:
        proc = self._proc
        if proc is not None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
            except ProcessLookupError:
                pass
            self._proc = None

        temp_path = self._temp_path
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            self._temp_path = None


class FakeImplementation(RunnerImplementation):
    """Bridge Pattern - Concrete Implementation for testing."""

    def __init__(self, listen: str = "127.0.0.1", start_port: int = 10808) -> None:
        self.listen = listen
        self.start_port = start_port

    async def start(self) -> SingBoxEndpoint:
        return SingBoxEndpoint(listen=self.listen, start_port=self.start_port)

    async def stop(self) -> None:
        pass


class RunnerAbstraction:
    """Bridge Pattern - Abstraction."""

    def __init__(self, implementation: RunnerImplementation) -> None:
        self._impl = implementation

    async def __aenter__(self) -> SingBoxEndpoint:
        return await self._impl.start()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: Any,
    ) -> None:
        await self._impl.stop()
