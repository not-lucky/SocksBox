from __future__ import annotations

import sys
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


def _response_carries_forbidden(body: str) -> bool:
    """Return True when the response body carries the ipinfo 403 markers."""
    return (
        IPINFO_FORBIDDEN_MARKER in body
        and IPINFO_FORBIDDEN_MARKER_PATH in body
    )


# Public alias for callers/tests that prefer non-underscored names.
response_carries_forbidden = _response_carries_forbidden


def mark_proxy_not_working(
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


# Backward-compatible alias used by existing tests and internal callers.
_mark_proxy_not_working = mark_proxy_not_working


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
