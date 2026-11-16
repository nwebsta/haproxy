"""Konfigurationsdatei der Anwendung (TOML)."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

DEFAULT_CONFIG_PATH = "/etc/haproxy-ui/config.toml"
ENV_VAR = "HAPROXY_UI_CONFIG"


@dataclass
class AppConfig:
    # Adresse der Weboberfläche. Nie über den verwalteten HAProxy veröffentlichen.
    listen_host: str = "127.0.0.1"
    listen_port: int = 8765
    database: Path = Path("/var/lib/haproxy-ui/haproxy-ui.db")
    haproxy_cfg: Path = Path("/etc/haproxy/haproxy.cfg")
    # Verzeichnis der Domainlisten; erscheint so in den "-f"-Pfaden der cfg.
    lists_dir: Path = Path("/etc/haproxy")
    backup_dir: Path = Path("/etc/haproxy/backup")
    haproxy_bin: str = "/usr/sbin/haproxy"
    reload_cmd: list[str] = field(
        default_factory=lambda: ["/usr/bin/sudo", "-n", "/usr/bin/systemctl", "reload", "haproxy"]
    )
    is_active_cmd: list[str] = field(
        default_factory=lambda: ["/usr/bin/systemctl", "is-active", "haproxy"]
    )
    # Nur auf true setzen, wenn die Oberfläche über HTTPS erreicht wird.
    cookie_secure: bool = False
    session_hours: int = 8
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    # HTTPS für die Oberfläche selbst. Beide gesetzt -> HTTPS, sonst HTTP.
    tls_cert: Path | None = None
    tls_key: Path | None = None

    @property
    def tls_enabled(self) -> bool:
        return self.tls_cert is not None and self.tls_key is not None


_PATH_FIELDS = {"database", "haproxy_cfg", "lists_dir", "backup_dir", "tls_cert", "tls_key"}


def load_config(path: str | os.PathLike | None = None) -> AppConfig:
    """Liest die Konfiguration. Ohne Datei gelten die Voreinstellungen."""
    explicit = path is not None or ENV_VAR in os.environ
    p = Path(path or os.environ.get(ENV_VAR, DEFAULT_CONFIG_PATH))
    cfg = AppConfig()
    if not p.exists():
        if explicit:
            raise FileNotFoundError(f"Konfigurationsdatei nicht gefunden: {p}")
        return cfg
    with p.open("rb") as fh:
        data = tomllib.load(fh)
    known = {f.name: f for f in fields(AppConfig)}
    for key, value in data.items():
        if key not in known:
            raise ValueError(f"Unbekannter Schlüssel in {p}: {key}")
        if key in _PATH_FIELDS:
            value = Path(value)
        elif key in ("reload_cmd", "is_active_cmd"):
            if not (isinstance(value, list) and value and all(isinstance(v, str) for v in value)):
                raise ValueError(f"{key} muss eine Liste von Zeichenketten sein")
        setattr(cfg, key, value)
    if (cfg.tls_cert is None) != (cfg.tls_key is None):
        raise ValueError(f"{p}: tls_cert und tls_key nur gemeinsam angeben")
    if cfg.tls_enabled:
        cfg.cookie_secure = True  # über HTTPS nur sichere Cookies
    return cfg
