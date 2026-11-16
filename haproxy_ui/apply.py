"""Prüfen, Anwenden und Zurückrollen.

Eine fehlerhafte Konfiguration darf nie den laufenden HAProxy erreichen:
  1. cfg + Domainlisten in ein temporäres Verzeichnis schreiben
  2. eigene Prüfungen
  3. haproxy -c -f <temporäre Datei>
  4. bisherige Dateien nach backup/<Zeitstempel>/ kopieren
  5. neue Dateien per Umbenennen an ihren Platz setzen
  6. systemctl reload haproxy
  7. systemctl is-active haproxy – bei Fehler Sicherung zurückspielen und erneut laden
  8. Fassung im Änderungsverlauf speichern
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import tempfile
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import AppConfig
from .db import set_setting
from .generator import Rendered, render
from .models import Version
from .state import export_state, load_state, resolve_domains
from .validation import InvalidInput, validate_state

Runner = Callable[[list[str]], "CmdResult"]
_LOCK = threading.Lock()


@dataclass
class CmdResult:
    returncode: int
    output: str


def run_command(argv: list[str], timeout: int = 60) -> CmdResult:
    """Externe Befehle nur als Argumentliste, nie über eine Shell."""
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, shell=False, check=False
        )
    except FileNotFoundError:
        return CmdResult(127, f"Programm nicht gefunden: {argv[0]}")
    except subprocess.TimeoutExpired:
        return CmdResult(124, f"Zeitüberschreitung nach {timeout} s: {' '.join(argv)}")
    return CmdResult(proc.returncode, (proc.stdout + proc.stderr).strip())


@dataclass
class CheckReport:
    errors: list[str]
    haproxy_ok: bool | None  # None = nicht ausgeführt
    haproxy_output: str
    rendered: Rendered | None

    @property
    def ok(self) -> bool:
        return not self.errors and self.haproxy_ok is True


@dataclass
class ApplyResult:
    ok: bool
    stage: str  # check | backup | install | reload | done
    message: str
    report: CheckReport | None = None
    details: list[str] = field(default_factory=list)
    backup_dir: Path | None = None
    version_id: int | None = None


def own_checks(state: dict) -> list[str]:
    errors: list[str] = []
    try:
        validate_state(state)
    except InvalidInput as exc:
        errors.append(str(exc))

    names = [s["name"] for s in state["services"]]
    for n in sorted({n for n in names if names.count(n) > 1}):
        errors.append(f"Dienstname {n} ist mehrfach vergeben")
    lnames = [l["name"] for l in state["domain_lists"]]
    for n in sorted({n for n in lnames if lnames.count(n) > 1}):
        errors.append(f"Domainliste {n} ist mehrfach vorhanden")
    lists = {l["name"]: l for l in state["domain_lists"]}

    owners: dict[str, list[str]] = defaultdict(list)
    for s in state["services"]:
        if not s["enabled"]:
            continue
        if s["domain_list"]:
            lst = lists.get(s["domain_list"])
            if lst is None:
                errors.append(f"Dienst {s['name']}: Domainliste {s['domain_list']} existiert nicht")
                continue
            if not lst["domains"]:
                errors.append(f"Dienst {s['name']}: Domainliste {s['domain_list']} ist leer")
        domains = resolve_domains(state, s)
        if not domains and not s["domain_list"]:
            errors.append(f"Dienst {s['name']}: keine Domains")
        for d in dict.fromkeys(domains):
            owners[d].append(s["name"])
    for d, who in owners.items():
        if len(who) > 1:
            errors.append(f"Domain {d} gehört zu mehreren aktiven Diensten: {', '.join(who)}")
    return errors


class Applier:
    def __init__(self, config: AppConfig, runner: Runner | None = None):
        self.config = config
        self.run = runner or run_command

    # -- Schritte 1–3 ---------------------------------------------------------
    def check(self, state: dict) -> CheckReport:
        errors = own_checks(state)
        try:
            rendered = render(state, self.config.lists_dir)
        except InvalidInput as exc:
            if str(exc) not in errors:
                errors.append(str(exc))
            return CheckReport(errors, None, "", None)

        tmp = Path(tempfile.mkdtemp(prefix="haproxy-ui-check-"))
        try:
            tmp_rendered = render(state, tmp)
            for name, text in tmp_rendered.lists.items():
                (tmp / name).write_text(text, encoding="utf-8")
            cfg_path = tmp / "haproxy.cfg"
            cfg_path.write_text(tmp_rendered.cfg, encoding="utf-8")
            res = self.run([self.config.haproxy_bin, "-c", "-f", str(cfg_path)])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        output = res.output.replace(str(tmp), str(self.config.lists_dir))
        return CheckReport(errors, res.returncode == 0, output, rendered)

    # -- Schritte 4–7 ---------------------------------------------------------
    def apply(self, state: dict) -> ApplyResult:
        with _LOCK:
            report = self.check(state)
            if not report.ok:
                return ApplyResult(False, "check", "Prüfung fehlgeschlagen – nichts wurde geändert.", report)
            targets = self._targets(report.rendered)
            try:
                backup_dir, backups = self._backup(list(targets))
            except OSError as exc:
                return ApplyResult(False, "backup", f"Sicherung fehlgeschlagen – nichts wurde geändert: {exc}", report)
            try:
                self._install(targets)
            except OSError as exc:
                details = self._restore(backups)
                return ApplyResult(
                    False, "install", f"Schreiben fehlgeschlagen, vorherige Dateien zurückgespielt: {exc}",
                    report, details, backup_dir,
                )

            reload = self.run(self.config.reload_cmd)
            active = self.run(self.config.is_active_cmd)
            if reload.returncode == 0 and active.returncode == 0:
                return ApplyResult(True, "done", "Konfiguration angewendet und HAProxy neu geladen.",
                                   report, [], backup_dir)

            details = [
                f"Neuladen: Rückgabewert {reload.returncode}" + (f"\n{reload.output}" if reload.output else ""),
                f"Status: {active.output or active.returncode}",
            ]
            details += self._restore(backups)
            again = self.run(self.config.reload_cmd)
            again_active = self.run(self.config.is_active_cmd)
            details.append(
                "Erneutes Laden der vorherigen Fassung: "
                + ("erfolgreich" if again.returncode == 0 and again_active.returncode == 0
                   else f"FEHLGESCHLAGEN ({again.output or again.returncode}; Status {again_active.output})")
            )
            return ApplyResult(
                False, "reload",
                "Neuladen fehlgeschlagen – die vorherige Fassung wurde wiederhergestellt.",
                report, details, backup_dir,
            )

    def _targets(self, rendered: Rendered) -> dict[Path, str]:
        targets = {self.config.lists_dir / name: text for name, text in rendered.lists.items()}
        targets[self.config.haproxy_cfg] = rendered.cfg  # cfg zuletzt
        return targets

    def _backup(self, paths: list[Path]) -> tuple[Path, dict[Path, Path | None]]:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        bdir = self.config.backup_dir / stamp
        bdir.mkdir(parents=True, exist_ok=False)
        backups: dict[Path, Path | None] = {}
        for p in paths:
            if p.exists():
                dest = bdir / p.name
                shutil.copy2(p, dest)
                backups[p] = dest
            else:
                backups[p] = None
        return bdir, backups

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
        tmp = path.parent / f".{path.name}.haproxy-ui-{secrets.token_hex(4)}"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                tmp.unlink()

    def _install(self, targets: dict[Path, str]) -> None:
        for path, text in targets.items():
            self._atomic_write(path, text.encode("utf-8"))

    def _restore(self, backups: dict[Path, Path | None]) -> list[str]:
        details = []
        for path, bpath in backups.items():
            try:
                if bpath is None:
                    path.unlink(missing_ok=True)
                else:
                    self._atomic_write(path, bpath.read_bytes())
            except OSError as exc:
                details.append(f"Zurückspielen von {path} fehlgeschlagen: {exc}")
        details.append("Vorherige Dateien aus der Sicherung zurückgespielt.")
        return details


# -- Datenbank-Seite: Anwenden, Verwerfen, Wiederherstellen ----------------------

PENDING_KEY = "pending_notes"


def pending_notes(db: Session) -> list[str]:
    from .db import get_setting

    try:
        return json.loads(get_setting(db, PENDING_KEY, "[]"))
    except ValueError:
        return []


def add_pending_note(db: Session, note: str) -> None:
    notes = pending_notes(db)
    if note not in notes:
        notes.append(note)
    set_setting(db, PENDING_KEY, json.dumps(notes, ensure_ascii=False))


def record_version(db: Session, state: dict, cfg_text: str, lists: dict[str, str], description: str) -> Version:
    v = Version(
        description=description or "Ohne Beschreibung",
        cfg_text=cfg_text,
        lists_json=json.dumps(lists, ensure_ascii=False),
        state_json=json.dumps(state, ensure_ascii=False),
    )
    db.add(v)
    db.flush()
    return v


def apply_current(db: Session, applier: Applier, description: str) -> ApplyResult:
    """Wendet den aktuellen Datenbankstand an und speichert bei Erfolg die Fassung."""
    state = export_state(db)
    result = applier.apply(state)
    if result.ok:
        v = record_version(db, state, result.report.rendered.cfg, result.report.rendered.lists, description)
        set_setting(db, PENDING_KEY, "[]")
        db.commit()
        result.version_id = v.id
    return result


def latest_version(db: Session) -> Version | None:
    return db.scalars(select(Version).order_by(Version.id.desc()).limit(1)).first()


def discard_changes(db: Session) -> bool:
    v = latest_version(db)
    if v is None:
        return False
    load_state(db, json.loads(v.state_json))
    set_setting(db, PENDING_KEY, "[]")
    db.commit()
    return True


def restore_version(db: Session, applier: Applier, version_id: int) -> ApplyResult:
    v = db.get(Version, version_id)
    if v is None:
        return ApplyResult(False, "check", "Fassung nicht gefunden.")
    db.commit()  # sauberer Ausgangspunkt für das Zurückrollen
    load_state(db, json.loads(v.state_json))
    stamp = v.created_at.strftime("%d.%m.%Y %H:%M")
    result = apply_current(db, applier, f"Wiederherstellung der Fassung #{v.id} vom {stamp} (UTC)")
    if not result.ok:
        # Nichts wurde angewendet – die Datenbank bleibt auf dem bisherigen Stand.
        db.rollback()
    return result
