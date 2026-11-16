"""Erzeugt haproxy.cfg und Domainlisten aus einem Datenstand (siehe state.py)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .validation import validate_state

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates_cfg"),
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
    undefined=StrictUndefined,
    autoescape=False,  # Klartext; alle Werte sind vorher streng geprüft
)


@dataclass
class Rendered:
    cfg: str
    lists: dict[str, str]  # Listenname -> Dateiinhalt


def server_line(ip: str, port: int, proxy: str, check: bool) -> str:
    parts = ["server", "server1", f"{ip}:{port}"]
    if proxy == "v1":
        parts.append("send-proxy")
    elif proxy == "v2":
        parts.append("send-proxy-v2")
    if check:
        parts.append("check")
    return " ".join(parts)


def list_file_text(domains: list[str]) -> str:
    return "".join(f"{d}\n" for d in domains)


def render(state: dict, lists_dir: Path | str) -> Rendered:
    """Erzeugt die Dateien. Listenpfade in der cfg zeigen auf `lists_dir`."""
    validate_state(state)
    lists_dir = PurePosixPath(str(lists_dir))
    ctx_services = []
    for s in state["services"]:
        if not s["enabled"]:
            continue
        if s["domain_list"]:
            acl_values = f"-i -f {lists_dir / s['domain_list']}"
        else:
            acl_values = "-i " + " ".join(s["domains"])
        ctx_services.append(
            {
                "name": s["name"],
                "acl": f"acl_{s['name']}",
                "acl_values": acl_values,
                "redirect": s["redirect_to_https"],
                "health_check": s["health_check"],
                "http_server": server_line(s["target_ip"], s["http_port"], s["http_proxy"], s["health_check"]),
                "https_server": server_line(s["target_ip"], s["https_port"], s["https_proxy"], s["health_check"]),
            }
        )
    cfg = _env.get_template("haproxy.cfg.j2").render(
        head=state["head"].strip("\n"),
        bind_ip=state["bind_ip"],
        services=ctx_services,
        redirects=[s for s in ctx_services if s["redirect"]],
    )
    lists = {lst["name"]: list_file_text(lst["domains"]) for lst in state["domain_lists"]}
    return Rendered(cfg=cfg, lists=lists)
