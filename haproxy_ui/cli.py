"""Kommandozeile: haproxy-ui import-cfg | create-admin | serve"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from sqlalchemy import func, select

from .apply import record_version
from .config import load_config
from .db import make_sessionmaker
from .importer import CfgImportError, parse_cfg
from .models import DomainList, Service, Version
from .state import load_state
from .validation import PROXY_LABELS


def cmd_import(config, args) -> int:
    cfg_path = Path(args.cfg) if args.cfg else config.haproxy_cfg
    read_dir = Path(args.lists_dir) if args.lists_dir else cfg_path.parent
    Session = make_sessionmaker(config.database)
    with Session() as db:
        existing = sum(db.scalar(select(func.count()).select_from(m)) for m in (Service, DomainList, Version))
        if existing:
            print("Die Datenbank enthält bereits Daten – der Import läuft nur einmal.", file=sys.stderr)
            return 2
        try:
            text = cfg_path.read_text(encoding="utf-8")
            result = parse_cfg(text, cfg_lists_dir=str(config.lists_dir), read_dir=read_dir)
        except CfgImportError as exc:
            print(f"Import abgebrochen – {cfg_path}, {exc}", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"Import abgebrochen: {exc}", file=sys.stderr)
            return 1
        load_state(db, result.state)
        # Ausgangsstand als erste Fassung, damit „Verwerfen“ und „Wiederherstellen“ funktionieren
        record_version(db, result.state, text, result.raw_lists, f"Import aus {cfg_path}")
        db.commit()

    for w in result.warnings:
        print(f"Warnung: {w}")
    print(f"Importiert: {len(result.state['services'])} Dienste, "
          f"{len(result.state['domain_lists'])} Domainlisten, Eingang {result.state['bind_ip']}")
    print(f"{'Name':<14} {'Domains':<32} {'Ziel-IP':<16} {'HTTP':<10} {'HTTPS':<10} Zustand")
    for s in result.state["services"]:
        doms = f"Liste {s['domain_list']}" if s["domain_list"] else ", ".join(s["domains"])
        http = f"{s['http_port']} {PROXY_LABELS[s['http_proxy']]}" + (" →" if s["redirect_to_https"] else "")
        https = f"{s['https_port']} {PROXY_LABELS[s['https_proxy']]}"
        print(f"{s['name']:<14} {doms[:32]:<32} {s['target_ip']:<16} {http:<10} {https:<10} "
              f"{'aktiv' if s['enabled'] else 'deaktiviert'}")
    print("Nichts wurde an HAProxy geändert. Weiter in der Oberfläche unter „Änderungen prüfen“.")
    return 0


def cmd_create_admin(config, args) -> int:
    from .auth import MIN_PASSWORD_LENGTH, set_admin

    password = getpass.getpass(f"Passwort für {args.username} (mind. {MIN_PASSWORD_LENGTH} Zeichen): ")
    if password != getpass.getpass("Passwort wiederholen: "):
        print("Die Passwörter stimmen nicht überein.", file=sys.stderr)
        return 1
    Session = make_sessionmaker(config.database)
    with Session() as db:
        try:
            set_admin(db, args.username, password)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    print(f"Admin-Konto {args.username} gespeichert. Bestehende Sitzungen wurden beendet.")
    return 0


def cmd_serve(config, args) -> int:
    import uvicorn

    from .web import create_app

    uvicorn.run(
        create_app(config),
        host=config.listen_host,
        port=config.listen_port,
        workers=1,
        proxy_headers=False,
        server_header=False,
        log_level="info",
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="haproxy-ui", description="Weboberfläche für HAProxy")
    p.add_argument("--config", help="Pfad zur config.toml (Voreinstellung: $HAPROXY_UI_CONFIG "
                                     "oder /etc/haproxy-ui/config.toml)")
    sub = p.add_subparsers(dest="cmd", required=True)
    imp = sub.add_parser("import-cfg", help="bestehende haproxy.cfg einmalig importieren")
    imp.add_argument("--cfg", help="zu importierende Datei (Voreinstellung: haproxy_cfg aus der Konfiguration)")
    imp.add_argument("--lists-dir", help="Verzeichnis, aus dem die Domainlisten gelesen werden "
                                         "(Voreinstellung: Verzeichnis der cfg)")
    adm = sub.add_parser("create-admin", help="Admin-Konto anlegen oder Passwort setzen")
    adm.add_argument("--username", default="admin")
    sub.add_parser("serve", help="Weboberfläche starten")
    args = p.parse_args(argv)
    config = load_config(args.config)
    return {"import-cfg": cmd_import, "create-admin": cmd_create_admin, "serve": cmd_serve}[args.cmd](config, args)


if __name__ == "__main__":
    sys.exit(main())
