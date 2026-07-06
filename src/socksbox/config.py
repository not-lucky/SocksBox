from __future__ import annotations

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
        self.start_port = 10808
        self.listen = "127.0.0.1"
        self.concurrency = 100
        self.tries = 5
        self.timeout = 4.0
        self.target_host = "cp.cloudflare.com"
        self.target_port = 80
        self.sing_box = "sing-box"
        self.ipinfo_token = ""
        self.no_enrich = False
        self.no_verify_ssl = False
        self.audit_log = None
        self.verbose = False

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
