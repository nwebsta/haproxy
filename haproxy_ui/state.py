"""Datenstand als einfaches dict – Grundlage für Erzeugung, Fassungen und Import.

Aufbau:
    {
      "bind_ip": "203.0.113.10",
      "head": "global\\n...",
      "domain_lists": [{"name": "kunde", "domains": ["a.example", ...]}],
      "services": [{"name": ..., "enabled": ..., "domains": [...], "domain_list": None | name,
                    "target_ip": ..., "http_port": ..., "http_proxy": ..., "https_port": ...,
                    "https_proxy": ..., "redirect_to_https": ..., "health_check": ...}]
    }
"""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .db import get_setting, set_setting
from .models import DomainList, Service

SERVICE_FIELDS = (
    "name",
    "enabled",
    "domains",
    "domain_list",
    "target_ip",
    "http_port",
    "http_proxy",
    "https_port",
    "https_proxy",
    "redirect_to_https",
    "health_check",
)


def service_to_dict(svc: Service) -> dict:
    return {
        "name": svc.name,
        "enabled": bool(svc.enabled),
        "domains": svc.domain_items,
        "domain_list": svc.domain_list.name if svc.domain_list else None,
        "target_ip": svc.target_ip,
        "http_port": svc.http_port,
        "http_proxy": svc.http_proxy,
        "https_port": svc.https_port,
        "https_proxy": svc.https_proxy,
        "redirect_to_https": bool(svc.redirect_to_https),
        "health_check": bool(svc.health_check),
    }


def export_state(db: Session) -> dict:
    lists = db.scalars(select(DomainList).order_by(DomainList.id)).all()
    services = db.scalars(select(Service).order_by(Service.id)).all()
    return {
        "bind_ip": get_setting(db, "bind_ip"),
        "head": get_setting(db, "head"),
        "domain_lists": [{"name": lst.name, "domains": lst.domain_items} for lst in lists],
        "services": [service_to_dict(s) for s in services],
    }


def load_state(db: Session, state: dict) -> None:
    """Ersetzt Dienste, Domainlisten und Einstellungen durch den gegebenen Stand."""
    db.execute(delete(Service))
    db.execute(delete(DomainList))
    db.flush()
    by_name: dict[str, DomainList] = {}
    for lst in state["domain_lists"]:
        obj = DomainList(name=lst["name"], domains="\n".join(lst["domains"]))
        db.add(obj)
        by_name[obj.name] = obj
    db.flush()
    for s in state["services"]:
        db.add(
            Service(
                name=s["name"],
                enabled=s["enabled"],
                domains="\n".join(s["domains"]),
                domain_list=by_name[s["domain_list"]] if s["domain_list"] else None,
                target_ip=s["target_ip"],
                http_port=s["http_port"],
                http_proxy=s["http_proxy"],
                https_port=s["https_port"],
                https_proxy=s["https_proxy"],
                redirect_to_https=s["redirect_to_https"],
                health_check=s["health_check"],
            )
        )
    set_setting(db, "bind_ip", state["bind_ip"])
    set_setting(db, "head", state["head"])
    db.flush()


def resolve_domains(state: dict, svc: dict) -> list[str]:
    if svc["domain_list"]:
        for lst in state["domain_lists"]:
            if lst["name"] == svc["domain_list"]:
                return list(lst["domains"])
        return []
    return list(svc["domains"])
