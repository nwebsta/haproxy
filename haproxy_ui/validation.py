"""Strenge Eingabeprüfung für alles, was in die haproxy.cfg gelangt.

Keine dieser Prüfungen lässt Leerzeichen, Zeilenumbrüche oder andere
Sonderzeichen durch, damit niemand eigene Konfigurationszeilen einschleusen kann.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ValidationError, model_validator

SERVICE_NAME_RE = re.compile(r"[a-z0-9_]{1,64}")
LIST_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
PORT_RE = re.compile(r"\d{1,5}")
LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

PROXY_MODES = ("off", "v1", "v2")
PROXY_LABELS = {"off": "aus", "v1": "v1", "v2": "v2"}
RESERVED_SERVICE_NAMES = {"http_in", "https_in"}
# Namen, die im Verzeichnis /etc/haproxy bereits belegt sind.
RESERVED_LIST_NAMES = {"errors", "backup"}


class InvalidInput(ValueError):
    """Eingabe verletzt die Regeln. Die Meldung ist für den Nutzer gedacht."""


def _require_str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise InvalidInput(f"{what}: Text erwartet")
    return value


def check_service_name(value: Any) -> str:
    v = _require_str(value, "Name")
    if not SERVICE_NAME_RE.fullmatch(v):
        raise InvalidInput("Name: nur a–z, 0–9 und _ erlaubt (1 bis 64 Zeichen)")
    if v in RESERVED_SERVICE_NAMES:
        raise InvalidInput(f"Name: „{v}“ ist reserviert")
    return v


def check_list_name(value: Any) -> str:
    v = _require_str(value, "Listenname")
    if not LIST_NAME_RE.fullmatch(v):
        raise InvalidInput(
            "Listenname: nur a–z, 0–9, _ und -, beginnend mit Buchstabe oder Ziffer (bis 64 Zeichen)"
        )
    if v in RESERVED_LIST_NAMES:
        raise InvalidInput(f"Listenname: „{v}“ ist reserviert")
    return v


def check_ipv4(value: Any) -> str:
    v = _require_str(value, "IP-Adresse")
    if not IPV4_RE.fullmatch(v):
        raise InvalidInput("IP-Adresse: IPv4 in der Form 192.168.1.10 erwartet")
    try:
        return str(ipaddress.IPv4Address(v))
    except ValueError:
        raise InvalidInput("IP-Adresse: ungültige IPv4-Adresse") from None


def check_port(value: Any) -> int:
    if isinstance(value, bool):
        raise InvalidInput("Port: Zahl erwartet")
    if isinstance(value, str):
        if not PORT_RE.fullmatch(value):
            raise InvalidInput("Port: Zahl von 1 bis 65535 erwartet")
        value = int(value)
    if not isinstance(value, int) or not 1 <= value <= 65535:
        raise InvalidInput("Port: Zahl von 1 bis 65535 erwartet")
    return value


def check_domain(value: Any) -> str:
    v = _require_str(value, "Domain").lower()
    if not v or len(v) > 253:
        raise InvalidInput(f"Domain „{value}“: Länge ungültig")
    labels = v.split(".")
    if len(labels) < 2:
        raise InvalidInput(f"Domain „{value}“: mindestens zwei Teile erwartet (z. B. host.example.de)")
    for label in labels:
        if not LABEL_RE.fullmatch(label):
            raise InvalidInput(f"Domain „{value}“: ungültig (erlaubt sind a–z, 0–9 und -)")
    if labels[-1].isdigit():
        raise InvalidInput(f"Domain „{value}“: letzte Stelle darf keine Zahl sein")
    return v


def check_proxy_mode(value: Any) -> str:
    if value not in PROXY_MODES:
        raise InvalidInput("PROXY-Modus: aus, v1 oder v2 erwartet")
    return value


def parse_domain_lines(value: Any, *, allow_comments: bool = False) -> list[str]:
    """Eine Domain pro Zeile. Leere Zeilen werden übersprungen, Dubletten abgelehnt."""
    if isinstance(value, list):
        lines = value
    else:
        lines = _require_str(value, "Domains").splitlines()
    result: list[str] = []
    seen: set[str] = set()
    for n, raw in enumerate(lines, 1):
        line = _require_str(raw, "Domain").strip()
        if not line or (allow_comments and line.startswith("#")):
            continue
        try:
            domain = check_domain(line)
        except InvalidInput as exc:
            raise InvalidInput(f"Zeile {n}: {exc}") from None
        if domain in seen:
            raise InvalidInput(f"Zeile {n}: Domain „{domain}“ steht doppelt")
        seen.add(domain)
        result.append(domain)
    return result


def normalize_head(value: Any) -> str:
    v = _require_str(value, "Kopfbereich").replace("\r\n", "\n").replace("\r", "\n")
    if "\x00" in v:
        raise InvalidInput("Kopfbereich: ungültige Zeichen")
    v = "\n".join(line.rstrip() for line in v.split("\n")).strip("\n")
    if not v.strip():
        raise InvalidInput("Kopfbereich darf nicht leer sein")
    return v


# --- Pydantic-Modelle für Formulare und den gespeicherten Datenstand -------------


def _wrap(fn):
    def inner(value):
        try:
            return fn(value)
        except InvalidInput as exc:
            raise ValueError(str(exc)) from None

    return BeforeValidator(inner)


def _optional_list_name(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return check_list_name(value)


ServiceName = Annotated[str, _wrap(check_service_name)]
IPv4 = Annotated[str, _wrap(check_ipv4)]
Port = Annotated[int, _wrap(check_port)]
ProxyMode = Annotated[str, _wrap(check_proxy_mode)]
Domains = Annotated[list[str], _wrap(parse_domain_lines)]
OptListName = Annotated[str | None, _wrap(_optional_list_name)]


class ServiceIn(BaseModel):
    name: ServiceName
    enabled: bool = True
    domains: Domains = []
    domain_list: OptListName = None
    target_ip: IPv4
    http_port: Port = 80
    http_proxy: ProxyMode = "off"
    https_port: Port = 443
    https_proxy: ProxyMode = "off"
    redirect_to_https: bool = False
    health_check: bool = False

    @model_validator(mode="after")
    def _domains_xor_list(self):
        if self.domain_list and self.domains:
            raise ValueError("Entweder Domains oder eine Domainliste angeben, nicht beides")
        if not self.domain_list and not self.domains:
            raise ValueError("Mindestens eine Domain oder eine Domainliste angeben")
        return self


class DomainListIn(BaseModel):
    name: Annotated[str, _wrap(check_list_name)]
    domains: Domains = []


def pydantic_errors(exc: ValidationError) -> dict[str, str]:
    """Wandelt Pydantic-Fehler in {feld: deutsche Meldung} um."""
    out: dict[str, str] = {}
    for err in exc.errors():
        field = str(err["loc"][0]) if err["loc"] else "_form"
        msg = err["msg"]
        if msg.startswith("Value error, "):
            msg = msg[len("Value error, "):]
        out.setdefault(field, msg)
    return out


def validate_state(state: dict) -> None:
    """Prüft einen kompletten Datenstand; wirft InvalidInput beim ersten Fehler.

    Wird vor jeder Erzeugung aufgerufen – auch Daten aus der Datenbank oder aus
    einer alten Fassung gelangen so nie ungeprüft in die Datei.
    """
    check_ipv4(state["bind_ip"])
    normalize_head(state["head"])
    for lst in state["domain_lists"]:
        try:
            DomainListIn.model_validate(lst)
        except ValidationError as exc:
            raise InvalidInput(f"Domainliste {lst.get('name')!r}: {_first(exc)}") from None
    for svc in state["services"]:
        try:
            ServiceIn.model_validate(svc)
        except ValidationError as exc:
            raise InvalidInput(f"Dienst {svc.get('name')!r}: {_first(exc)}") from None


def _first(exc: ValidationError) -> str:
    return next(iter(pydantic_errors(exc).values()))
