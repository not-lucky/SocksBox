"""Tests for socksbox.status forbidden-response helpers."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

from socksbox.models import ProxyInfo
from socksbox.status import (
    DEFAULT_AUDIT_LOG_NAME,
    IPINFO_FORBIDDEN_MARKER,
    IPINFO_FORBIDDEN_MARKER_PATH,
    IPINFO_FORBIDDEN_STATUS,
    _mark_proxy_not_working,
    _response_carries_forbidden,
    log_forbidden_detection,
    mark_proxy_not_working,
    response_carries_forbidden,
)


def _dummy_proxy(**kwargs: Any) -> ProxyInfo:
    defaults: dict[str, Any] = {
        "link": "socks5://127.0.0.1:1080",
        "protocol": "socks5",
        "label": "dummy",
        "outbound": {},
    }
    defaults.update(kwargs)
    return ProxyInfo(**defaults)


class TestForbiddenConstants:
    def test_ipinfo_forbidden_marker_is_exact_google_message(self) -> None:
        assert "permission to get URL" in IPINFO_FORBIDDEN_MARKER

    def test_ipinfo_forbidden_marker_path_is_json_code_tag(self) -> None:
        assert IPINFO_FORBIDDEN_MARKER_PATH == "<code>/json</code>"

    def test_ipinfo_forbidden_status_is_403(self) -> None:
        assert IPINFO_FORBIDDEN_STATUS == 403

    def test_default_audit_log_name(self) -> None:
        assert DEFAULT_AUDIT_LOG_NAME == "forbidden_detections.log"


class TestResponseCarriesForbidden:
    def test_true_when_both_markers_present(self) -> None:
        body = (
            f"<p>{IPINFO_FORBIDDEN_MARKER} /json from this server</p>"
            f"<p>{IPINFO_FORBIDDEN_MARKER_PATH}</p>"
        )
        assert response_carries_forbidden(body) is True

    def test_false_when_marker_missing(self) -> None:
        body = f"<p>{IPINFO_FORBIDDEN_MARKER_PATH}</p>"
        assert response_carries_forbidden(body) is False

    def test_false_when_path_missing(self) -> None:
        body = f"<p>{IPINFO_FORBIDDEN_MARKER}</p>"
        assert response_carries_forbidden(body) is False

    def test_false_for_empty_string(self) -> None:
        assert response_carries_forbidden("") is False

    def test_false_for_unrelated_text(self) -> None:
        assert response_carries_forbidden("OK response from ipinfo.io") is False

    def test_public_name_aliases_private_helper(self) -> None:
        assert response_carries_forbidden is _response_carries_forbidden


class TestMarkProxyNotWorking:
    def test_sets_latency_to_infinity(self) -> None:
        proxy = _dummy_proxy(latency_ms=42.0)
        mark_proxy_not_working(proxy, "forbidden")
        assert proxy.latency_ms == float("inf")
        assert proxy.working is False

    def test_records_forbidden_check_diagnostics(self) -> None:
        proxy = _dummy_proxy()
        mark_proxy_not_working(proxy, "ipinfo.io forbidden 403 response")

        diag = proxy.diagnostics["forbidden_check"]
        assert diag["status"] == "not_working"
        assert diag["reason"] == "ipinfo.io forbidden 403 response"
        assert "detected_at" in diag
        assert diag["detected_at"].endswith("+00:00")

    def test_merges_extra_diagnostics(self) -> None:
        proxy = _dummy_proxy()
        extra = {"http_status": 403, "socks_port": 10808}
        mark_proxy_not_working(proxy, "forbidden", extra=extra)

        diag = proxy.diagnostics["forbidden_check"]
        assert diag["http_status"] == 403
        assert diag["socks_port"] == 10808

    def test_preserves_existing_diagnostics(self) -> None:
        proxy = _dummy_proxy()
        proxy.diagnostics["existing"] = {"value": 1}
        mark_proxy_not_working(proxy, "forbidden")

        assert proxy.diagnostics["existing"] == {"value": 1}
        assert "forbidden_check" in proxy.diagnostics

    def test_public_name_aliases_private_helper(self) -> None:
        assert mark_proxy_not_working is _mark_proxy_not_working

    def test_second_call_updates_status_and_reason(self) -> None:
        proxy = _dummy_proxy(latency_ms=12.0)
        mark_proxy_not_working(proxy, "first")
        first_detected_at = proxy.diagnostics["forbidden_check"]["detected_at"]
        mark_proxy_not_working(proxy, "second", extra={"http_status": 503})

        diag = proxy.diagnostics["forbidden_check"]
        assert diag["reason"] == "second"
        assert diag["http_status"] == 503
        assert diag["detected_at"] != first_detected_at
        assert proxy.latency_ms == float("inf")
        assert proxy.working is False


class TestLogForbiddenDetection:
    def test_prints_to_stderr(self, capsys: pytest.CaptureFixture[str]) -> None:
        proxy = _dummy_proxy(ip="1.2.3.4")
        log_forbidden_detection(proxy, socks_port=10808, http_status=403)

        captured = capsys.readouterr()
        assert "proxy_marked_not_working" in captured.err
        assert "reason=ipinfo_forbidden_403" in captured.err
        assert "http_status=403" in captured.err
        assert "socks_port=10808" in captured.err
        assert "proxy_ip=1.2.3.4" in captured.err

    def test_fallback_proxy_ip_uses_label(self, capsys: pytest.CaptureFixture[str]) -> None:
        proxy = _dummy_proxy(ip="", label="my-label")
        log_forbidden_detection(proxy, socks_port=10808)

        captured = capsys.readouterr()
        assert "proxy_ip=my-label" in captured.err

    def test_fallback_proxy_ip_uses_link(self, capsys: pytest.CaptureFixture[str]) -> None:
        proxy = _dummy_proxy(ip="", label="")
        log_forbidden_detection(proxy, socks_port=10808)

        captured = capsys.readouterr()
        assert "proxy_ip=socks5://127.0.0.1:1080" in captured.err

    def test_writes_to_audit_log_file(self, tmp_path: Path) -> None:
        audit_path = tmp_path / DEFAULT_AUDIT_LOG_NAME
        proxy = _dummy_proxy(ip="5.6.7.8")
        log_forbidden_detection(proxy, socks_port=19000, audit_log_path=audit_path, http_status=403)

        assert audit_path.exists()
        content = audit_path.read_text(encoding="utf-8")
        assert "proxy_marked_not_working" in content
        assert "proxy_ip=5.6.7.8" in content
        assert content.endswith("\n")

    def test_unknown_http_status_when_not_provided(self, capsys: pytest.CaptureFixture[str]) -> None:
        proxy = _dummy_proxy()
        log_forbidden_detection(proxy, socks_port=10808)

        captured = capsys.readouterr()
        assert "http_status=unknown" in captured.err

    def test_creates_missing_parent_directories(self, tmp_path: Path) -> None:
        audit_path = tmp_path / "nested" / "dir" / DEFAULT_AUDIT_LOG_NAME
        proxy = _dummy_proxy(ip="9.10.11.12")
        log_forbidden_detection(proxy, socks_port=10808, audit_log_path=audit_path, http_status=403)

        assert audit_path.exists()
        content = audit_path.read_text(encoding="utf-8")
        assert "proxy_ip=9.10.11.12" in content

    def test_appends_multiple_entries(self, tmp_path: Path) -> None:
        audit_path = tmp_path / DEFAULT_AUDIT_LOG_NAME
        proxy = _dummy_proxy(ip="1.1.1.1")
        log_forbidden_detection(proxy, socks_port=10808, audit_log_path=audit_path, http_status=403)
        log_forbidden_detection(proxy, socks_port=10809, audit_log_path=audit_path, http_status=403)

        lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2
        assert "socks_port=10808" in lines[0]
        assert "socks_port=10809" in lines[1]
