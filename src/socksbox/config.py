from __future__ import annotations

import os
from typing import Any, List, Protocol


class ConfigObserver(Protocol):
    """Observer pattern: observer interface for configuration updates."""

    def on_config_change(self, config: AppConfig) -> None:
        ...


class AppConfig:
    """Singleton pattern: application-wide settings.
    Observer pattern: notifies observers when config changes.
    """

    _instance: AppConfig | None = None

    def __new__(cls) -> AppConfig:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_defaults()
        return cls._instance

    @classmethod
    def instance(cls) -> AppConfig:
        return cls()

    def _init_defaults(self) -> None:
        self._observers: List[ConfigObserver] = []
        self.start_port = int(os.environ.get("START_PORT", "10808"))
        self.listen = os.environ.get("LISTEN", "127.0.0.1")
        self.concurrency = int(os.environ.get("CONCURRENCY", "100"))
        self.tries = int(os.environ.get("TRIES", "5"))
        self.timeout = float(os.environ.get("TIMEOUT", "4.0"))
        self.target_host = os.environ.get("TARGET_HOST", "cp.cloudflare.com")
        self.target_port = int(os.environ.get("TARGET_PORT", "80"))
        self.sing_box = os.environ.get("SING_BOX", "sing-box")
        self.ipinfo_token = os.environ.get("IPINFO_TOKEN", "")
        self.abuseipdb_token = os.environ.get("ABUSEIPDB_TOKEN", "")
        self.enrich_providers = os.environ.get("ENRICH_PROVIDERS", "ipinfo")
        self.no_enrich = os.environ.get("NO_ENRICH", "").lower() in ("true", "1")
        self.no_verify_ssl = os.environ.get("NO_VERIFY_SSL", "").lower() in ("true", "1")
        self.audit_log = os.environ.get("AUDIT_LOG", None)
        self.verbose = os.environ.get("VERBOSE", "").lower() in ("true", "1")
        
        # Extra and stage-specific configuration
        self.output_dir = os.environ.get("OUTPUT_DIR", "output")
        self.download_test = os.environ.get("DOWNLOAD_TEST", "").lower() in ("true", "1")
        self.download_url = os.environ.get("DOWNLOAD_URL", "https://speed.cloudflare.com/__down?bytes=1048576")
        self.download_timeout = float(os.environ.get("DOWNLOAD_TIMEOUT", "30.0"))
        self.download_concurrency = int(os.environ.get("DOWNLOAD_CONCURRENCY", "5"))
        self.legacy_route = os.environ.get("LEGACY_ROUTE", "").lower() in ("true", "1")

    def update_from_dict(self, data: dict[str, Any]) -> None:
        for k, v in data.items():
            if hasattr(self, k):
                setattr(self, k, v)
        self.notify_observers()

    def register_observer(self, observer: ConfigObserver) -> None:
        if observer not in self._observers:
            self._observers.append(observer)

    def remove_observer(self, observer: ConfigObserver) -> None:
        if observer in self._observers:
            self._observers.remove(observer)

    def notify_observers(self) -> None:
        for observer in self._observers:
            observer.on_config_change(self)
