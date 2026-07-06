from __future__ import annotations

from typing import Any, Protocol, runtime_checkable
from socksbox.runner.bridge import (
    FakeImplementation,
    RunnerAbstraction,
    RunnerImplementation,
    SingBoxEndpoint,
    SubprocessImplementation,
)
from socksbox.runner.proxy import LoggingRunnerProxy


@runtime_checkable
class SingBoxRunner(Protocol):
    """Protocol for adapters that manage a sing-box subprocess lifecycle."""

    async def __aenter__(self) -> SingBoxEndpoint: ...
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: Any,
    ) -> None: ...


class SubprocessSingBoxRunner(LoggingRunnerProxy):
    """Subclass implementing LoggingRunnerProxy for a SubprocessImplementation."""

    def __init__(self, config: dict, **kwargs) -> None:
        self.impl = SubprocessImplementation(config, **kwargs)
        runner = RunnerAbstraction(self.impl)
        super().__init__(runner)

    @property
    def config(self):
        return self.impl.config

    @property
    def sing_box(self):
        return self.impl.sing_box

    @property
    def listen(self):
        return self.impl.listen

    @property
    def start_port(self):
        return self.impl.start_port

    @property
    def startup_delay(self):
        return self.impl.startup_delay

    @property
    def _temp_path(self):
        return self.impl._temp_path

    @_temp_path.setter
    def _temp_path(self, val):
        self.impl._temp_path = val

    @property
    def _proc(self):
        return self.impl._proc

    @_proc.setter
    def _proc(self, val):
        self.impl._proc = val

    def _cleanup(self):
        self.impl._cleanup()


class FakeSingBoxRunner(RunnerAbstraction):
    """Subclass implementing RunnerAbstraction for a FakeImplementation."""

    def __init__(self, **kwargs) -> None:
        impl = FakeImplementation(**kwargs)
        super().__init__(impl)


__all__ = [
    "SingBoxEndpoint",
    "RunnerImplementation",
    "SubprocessImplementation",
    "FakeImplementation",
    "RunnerAbstraction",
    "LoggingRunnerProxy",
    "SubprocessSingBoxRunner",
    "FakeSingBoxRunner",
    "SingBoxRunner",
]
