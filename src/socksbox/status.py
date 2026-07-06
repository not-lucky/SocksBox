from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Protocol

from socksbox.models import ProxyInfo


# Markers from Google's 403 Forbidden block page served when an IP has been
# flagged. The exact substring must appear in the curl response body for the
# proxy to be considered "not working" by the validation check.
IPINFO_FORBIDDEN_MARKER = "Your client does not have permission to get URL"
IPINFO_FORBIDDEN_MARKER_PATH = "<code>/json</code>"
IPINFO_FORBIDDEN_STATUS = 403
DEFAULT_AUDIT_LOG_NAME = "forbidden_detections.log"


def response_carries_forbidden(body: str) -> bool:
    """Return True when the response body carries the ipinfo 403 markers."""
    return (
        IPINFO_FORBIDDEN_MARKER in body
        and IPINFO_FORBIDDEN_MARKER_PATH in body
    )


# Backward-compatible alias
_response_carries_forbidden = response_carries_forbidden


class ProxyStatusObserver(Protocol):
    """Observer pattern: interface for components observing proxy status changes."""

    def on_proxy_blocked(self, proxy: ProxyInfo, reason: str, extra: dict[str, Any]) -> None:
        ...

    def on_proxy_working(self, proxy: ProxyInfo) -> None:
        ...


class StderrObserver:
    """Concrete observer: prints proxy status updates to stderr."""

    def on_proxy_blocked(self, proxy: ProxyInfo, reason: str, extra: dict[str, Any]) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        proxy_ip = proxy.ip or proxy.label or proxy.link
        socks_port = extra.get("socks_port", "unknown")
        http_status = extra.get("http_status", "unknown")
        message = (
            f"[{timestamp}] proxy_marked_not_working "
            f"reason={reason} "
            f"http_status={http_status} "
            f"socks_port={socks_port} "
            f"proxy_ip={proxy_ip}"
        )
        print(message, file=sys.stderr)

    def on_proxy_working(self, proxy: ProxyInfo) -> None:
        pass


class AuditLogObserver:
    """Concrete observer: writes forbidden detections to a file."""

    def __init__(self, audit_log_path: Path | None = None) -> None:
        self.audit_log_path = audit_log_path

    def on_proxy_blocked(self, proxy: ProxyInfo, reason: str, extra: dict[str, Any]) -> None:
        if self.audit_log_path is None:
            return
        timestamp = datetime.now(timezone.utc).isoformat()
        proxy_ip = proxy.ip or proxy.label or proxy.link
        socks_port = extra.get("socks_port", "unknown")
        http_status = extra.get("http_status", "unknown")
        message = (
            f"[{timestamp}] proxy_marked_not_working "
            f"reason={reason} "
            f"http_status={http_status} "
            f"socks_port={socks_port} "
            f"proxy_ip={proxy_ip}"
        )
        try:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_log_path.open("a", encoding="utf-8") as f:
                f.write(message + "\n")
        except Exception as exc:
            print(f"Failed to write to audit log: {exc}", file=sys.stderr)

    def on_proxy_working(self, proxy: ProxyInfo) -> None:
        pass


class ProxyStatusRegistry:
    """Subject/Publisher for proxy status updates."""

    def __init__(self) -> None:
        self._observers: List[ProxyStatusObserver] = [StderrObserver()]

    def register_observer(self, observer: ProxyStatusObserver) -> None:
        if observer not in self._observers:
            self._observers.append(observer)

    def remove_observer(self, observer: ProxyStatusObserver) -> None:
        if observer in self._observers:
            self._observers.remove(observer)

    def clear_observers_by_class(self, cls: type) -> None:
        self._observers = [obs for obs in self._observers if not isinstance(obs, cls)]

    def notify_blocked(self, proxy: ProxyInfo, reason: str, extra: dict[str, Any]) -> None:
        for observer in self._observers:
            observer.on_proxy_blocked(proxy, reason, extra)

    def notify_working(self, proxy: ProxyInfo) -> None:
        for observer in self._observers:
            observer.on_proxy_working(proxy)


GLOBAL_STATUS_REGISTRY = ProxyStatusRegistry()


def mark_proxy_not_working(
    proxy: ProxyInfo,
    reason: str,
    extra: dict[str, Any] | None = None,
) -> None:
    """Flip a proxy's status to not working, record diagnostics, and notify observers."""
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
    GLOBAL_STATUS_REGISTRY.notify_blocked(proxy, reason, extra or {})


# Backward-compatible alias
_mark_proxy_not_working = mark_proxy_not_working


def log_forbidden_detection(
    proxy: ProxyInfo,
    socks_port: int,
    audit_log_path: Path | None = None,
    http_status: int | None = None,
) -> None:
    """Trigger notifications specifically for forbidden IP detection."""
    # Ensure audit log observer is configured
    if audit_log_path:
        # Clear existing ones first to avoid duplicate logs if already registered
        GLOBAL_STATUS_REGISTRY.clear_observers_by_class(AuditLogObserver)
        GLOBAL_STATUS_REGISTRY.register_observer(AuditLogObserver(audit_log_path))
    
    # Notification logic is already handled during mark_proxy_not_working
    # but we support this as a standalone helper
    extra = {
        "socks_port": socks_port,
        "http_status": http_status if http_status is not None else "unknown",
    }
    # If the proxy isn't already marked not working, notify
    GLOBAL_STATUS_REGISTRY.notify_blocked(proxy, "ipinfo_forbidden_403", extra)
