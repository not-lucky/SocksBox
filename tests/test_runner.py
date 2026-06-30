"""Tests for the sing-box runner seam."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from socksbox.runner import (
    FakeSingBoxRunner,
    SingBoxEndpoint,
    SingBoxRunner,
    SubprocessSingBoxRunner,
)


class TestSingBoxEndpoint:
    def test_endpoint_fields(self) -> None:
        endpoint = SingBoxEndpoint(listen="127.0.0.1", start_port=10808)
        assert endpoint.listen == "127.0.0.1"
        assert endpoint.start_port == 10808


class TestFakeSingBoxRunner:
    @pytest.mark.asyncio
    async def test_yields_configured_endpoint(self) -> None:
        runner = FakeSingBoxRunner(listen="192.168.1.1", start_port=19000)
        async with runner as endpoint:
            assert endpoint == SingBoxEndpoint(listen="192.168.1.1", start_port=19000)

    @pytest.mark.asyncio
    async def test_uses_default_values(self) -> None:
        runner = FakeSingBoxRunner()
        async with runner as endpoint:
            assert endpoint.listen == "127.0.0.1"
            assert endpoint.start_port == 10808

    @pytest.mark.asyncio
    async def test_is_reusable(self) -> None:
        runner = FakeSingBoxRunner(listen="10.0.0.1", start_port=20000)
        async with runner as first:
            assert first.start_port == 20000
        async with runner as second:
            assert second.start_port == 20000

    @pytest.mark.asyncio
    async def test_exception_in_body_propagates(self) -> None:
        runner = FakeSingBoxRunner()
        with pytest.raises(ValueError, match="body error"):
            async with runner:
                raise ValueError("body error")

    @pytest.mark.asyncio
    async def test_aexit_returns_none(self) -> None:
        runner = FakeSingBoxRunner()
        result = await runner.__aexit__(None, None, None)
        assert result is None

    def test_satisfies_runner_protocol(self) -> None:
        assert isinstance(FakeSingBoxRunner(), SingBoxRunner)

    @pytest.mark.asyncio
    async def test_reusable_after_body_exception(self) -> None:
        runner = FakeSingBoxRunner(listen="127.0.0.1", start_port=30000)
        with pytest.raises(RuntimeError, match="boom"):
            async with runner:
                raise RuntimeError("boom")
        async with runner as endpoint:
            assert endpoint == SingBoxEndpoint(
                listen="127.0.0.1", start_port=30000
            )


class TestSubprocessSingBoxRunner:
    @pytest.fixture
    def alive_process(self) -> MagicMock:
        process = MagicMock()
        process.poll.return_value = None
        process.returncode = None
        return process

    @pytest.fixture
    def fake_popen(self, monkeypatch: Any) -> MagicMock:
        mock = MagicMock()
        monkeypatch.setattr(subprocess, "Popen", mock)
        return mock

    @pytest.mark.asyncio
    async def test_writes_config_and_yields_endpoint(
        self,
        tmp_path: Path,
        monkeypatch: Any,
        alive_process: MagicMock,
    ) -> None:
        config = {"log": {"level": "warn"}, "inbounds": []}
        captured_cmd: list[str] | None = None

        def fake_popen(cmd: list[str], **kwargs: Any) -> MagicMock:
            nonlocal captured_cmd
            captured_cmd = cmd
            return alive_process

        monkeypatch.setattr(subprocess, "Popen", fake_popen)

        runner = SubprocessSingBoxRunner(
            config=config,
            sing_box="sing-box",
            listen="127.0.0.1",
            start_port=10808,
            startup_delay=0.01,
        )

        async with runner as endpoint:
            assert endpoint.listen == "127.0.0.1"
            assert endpoint.start_port == 10808
            assert runner._temp_path is not None
            assert runner._temp_path.exists()
            assert captured_cmd == ["sing-box", "run", "-c", str(runner._temp_path)]
            written = runner._temp_path.read_text(encoding="utf-8")
            assert '"level": "warn"' in written
            assert '"inbounds": []' in written

        alive_process.terminate.assert_called_once()
        alive_process.wait.assert_called_once_with(timeout=5)
        assert runner._temp_path is None

    @pytest.mark.asyncio
    async def test_raises_and_cleans_up_when_process_dies(
        self,
        monkeypatch: Any,
    ) -> None:
        dead_process = MagicMock()
        dead_process.poll.return_value = 1
        dead_process.returncode = 1

        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: dead_process)

        runner = SubprocessSingBoxRunner(
            config={},
            startup_delay=0.01,
        )

        with pytest.raises(RuntimeError, match="sing-box terminated early"):
            async with runner:
                pass  # pragma: no cover

        dead_process.terminate.assert_called_once()
        assert runner._temp_path is None
        assert runner._proc is None

    @pytest.mark.asyncio
    async def test_kills_process_when_terminate_times_out(
        self,
        monkeypatch: Any,
        alive_process: MagicMock,
    ) -> None:
        alive_process.wait.side_effect = [
            subprocess.TimeoutExpired("sing-box", 5),
            None,
        ]

        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: alive_process)

        runner = SubprocessSingBoxRunner(
            config={},
            startup_delay=0.01,
        )

        async with runner:
            pass

        alive_process.terminate.assert_called_once()
        alive_process.kill.assert_called_once()
        assert alive_process.wait.call_count == 2

    @pytest.mark.asyncio
    async def test_kills_process_when_wait_after_kill_times_out(
        self,
        monkeypatch: Any,
        alive_process: MagicMock,
    ) -> None:
        alive_process.wait.side_effect = [
            subprocess.TimeoutExpired("sing-box", 5),
            subprocess.TimeoutExpired("sing-box", 2),
        ]

        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: alive_process)

        runner = SubprocessSingBoxRunner(
            config={},
            startup_delay=0.01,
        )

        async with runner:
            pass

        alive_process.terminate.assert_called_once()
        alive_process.kill.assert_called_once()
        assert alive_process.wait.call_count == 2

    @pytest.mark.asyncio
    async def test_cleanup_tolerates_missing_process(
        self,
        monkeypatch: Any,
        alive_process: MagicMock,
    ) -> None:
        alive_process.terminate.side_effect = ProcessLookupError(123)

        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: alive_process)

        runner = SubprocessSingBoxRunner(
            config={},
            startup_delay=0.01,
        )

        async with runner:
            pass

        alive_process.terminate.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_runs_when_body_raises(
        self,
        monkeypatch: Any,
        alive_process: MagicMock,
    ) -> None:
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: alive_process)

        runner = SubprocessSingBoxRunner(
            config={},
            startup_delay=0.01,
        )

        with pytest.raises(RuntimeError, match="boom"):
            async with runner as endpoint:
                assert isinstance(endpoint, SingBoxEndpoint)
                raise RuntimeError("boom")

        alive_process.terminate.assert_called_once()

    @pytest.mark.asyncio
    async def test_popen_failure_cleans_up_temp_file(
        self,
        tmp_path: Path,
        monkeypatch: Any,
    ) -> None:
        target = tmp_path / "leaked.json"

        def fake_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
            fd = os.open(target, os.O_CREAT | os.O_WRONLY)
            return fd, str(target)

        monkeypatch.setattr(tempfile, "mkstemp", fake_mkstemp)

        def failing_popen(*args: Any, **kwargs: Any) -> MagicMock:
            raise FileNotFoundError("sing-box")

        monkeypatch.setattr(subprocess, "Popen", failing_popen)

        runner = SubprocessSingBoxRunner(
            config={},
            startup_delay=0.01,
        )

        with pytest.raises(FileNotFoundError, match="sing-box"):
            async with runner:
                pass  # pragma: no cover

        assert runner._temp_path is None
        assert not target.exists()

    @pytest.mark.asyncio
    async def test_popen_receives_output_suppression(
        self,
        monkeypatch: Any,
        alive_process: MagicMock,
    ) -> None:
        captured: dict[str, Any] = {}

        def fake_popen(*args: Any, **kwargs: Any) -> MagicMock:
            captured["kwargs"] = kwargs
            return alive_process

        monkeypatch.setattr(subprocess, "Popen", fake_popen)

        async with SubprocessSingBoxRunner(
            config={},
            startup_delay=0.01,
        ):
            pass

        assert captured["kwargs"]["stdout"] is subprocess.DEVNULL
        assert captured["kwargs"]["stderr"] is subprocess.DEVNULL

    @pytest.mark.asyncio
    async def test_custom_sing_box_path(
        self,
        monkeypatch: Any,
        alive_process: MagicMock,
    ) -> None:
        captured_cmd: list[str] | None = None

        def fake_popen(cmd: list[str], **kwargs: Any) -> MagicMock:
            nonlocal captured_cmd
            captured_cmd = cmd
            return alive_process

        monkeypatch.setattr(subprocess, "Popen", fake_popen)

        async with SubprocessSingBoxRunner(
            config={},
            sing_box="/usr/local/bin/sing-box",
            startup_delay=0.01,
        ):
            pass

        assert captured_cmd is not None
        assert captured_cmd[0] == "/usr/local/bin/sing-box"

    @pytest.mark.asyncio
    async def test_unicode_config_round_trips_without_escape(
        self,
        monkeypatch: Any,
        alive_process: MagicMock,
    ) -> None:
        config = {"inbounds": [{"tag": "日本語"}]}
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: alive_process)

        runner = SubprocessSingBoxRunner(
            config=config,
            startup_delay=0.01,
        )

        async with runner as endpoint:
            assert isinstance(endpoint, SingBoxEndpoint)
            written = runner._temp_path.read_text(encoding="utf-8")
            assert "日本語" in written

    @pytest.mark.asyncio
    async def test_cleanup_removes_temp_file_after_body_exception(
        self,
        monkeypatch: Any,
        alive_process: MagicMock,
    ) -> None:
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: alive_process)

        runner = SubprocessSingBoxRunner(
            config={},
            startup_delay=0.01,
        )
        temp_path: Path | None = None

        with pytest.raises(RuntimeError, match="boom"):
            async with runner as endpoint:
                temp_path = runner._temp_path
                assert isinstance(endpoint, SingBoxEndpoint)
                assert temp_path is not None
                assert temp_path.exists()
                raise RuntimeError("boom")

        assert runner._temp_path is None
        assert temp_path is not None
        assert not temp_path.exists()
        alive_process.terminate.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_idempotent(
        self,
        monkeypatch: Any,
        alive_process: MagicMock,
    ) -> None:
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: alive_process)

        runner = SubprocessSingBoxRunner(
            config={},
            startup_delay=0.01,
        )

        async with runner:
            pass

        alive_process.terminate.assert_called_once()

        runner._cleanup()

        assert alive_process.terminate.call_count == 1
        assert runner._proc is None
        assert runner._temp_path is None

    @pytest.mark.asyncio
    async def test_cleanup_works_when_process_already_none(
        self,
        tmp_path: Path,
    ) -> None:
        runner = SubprocessSingBoxRunner(config={})
        leftover = tmp_path / "manual.json"
        leftover.write_text("{}", encoding="utf-8")
        runner._temp_path = leftover
        runner._proc = None

        runner._cleanup()

        assert runner._temp_path is None
        assert not leftover.exists()

    @pytest.mark.asyncio
    async def test_satisfies_runner_protocol(
        self,
        monkeypatch: Any,
        alive_process: MagicMock,
    ) -> None:
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: alive_process)

        runner = SubprocessSingBoxRunner(
            config={},
            startup_delay=0.01,
        )

        assert isinstance(runner, SingBoxRunner)

        async with runner:
            pass

    @pytest.mark.asyncio
    async def test_terminate_wait_succeeds_without_kill(
        self,
        monkeypatch: Any,
        alive_process: MagicMock,
    ) -> None:
        alive_process.wait.return_value = None
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: alive_process)

        async with SubprocessSingBoxRunner(
            config={},
            startup_delay=0.01,
        ):
            pass

        alive_process.terminate.assert_called_once()
        alive_process.wait.assert_called_once_with(timeout=5)
        alive_process.kill.assert_not_called()
