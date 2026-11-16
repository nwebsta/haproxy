from __future__ import annotations

import json

import pytest

from haproxy_ui.apply import (
    Applier,
    CmdResult,
    apply_current,
    discard_changes,
    own_checks,
    pending_notes,
    record_version,
    restore_version,
)
from haproxy_ui.config import AppConfig
from haproxy_ui.db import make_sessionmaker
from haproxy_ui.models import Service, Version
from haproxy_ui.state import export_state, load_state

ORIGINAL = "# laufende Datei\n"


class FakeRunner:
    """Ersetzt haproxy/systemctl. Antworten werden pro Programm vorgegeben."""

    def __init__(self, check_ok=True, reload_results=(0,), active_results=(0,)):
        self.check_ok = check_ok
        self.reload_results = list(reload_results)
        self.active_results = list(active_results)
        self.calls: list[list[str]] = []
        self.checked_cfg: str | None = None

    def __call__(self, argv):
        self.calls.append(argv)
        if "-c" in argv:
            self.checked_cfg = open(argv[argv.index("-f") + 1]).read()
            if self.check_ok:
                return CmdResult(0, "Configuration file is valid")
            return CmdResult(1, "[ALERT]    (1) : config : parsing [haproxy.cfg:12] : unknown keyword 'bogus'")
        if "reload" in argv:
            rc = self.reload_results.pop(0) if self.reload_results else 0
            return CmdResult(rc, "" if rc == 0 else "Job for haproxy.service failed.")
        if "is-active" in argv:
            rc = self.active_results.pop(0) if self.active_results else 0
            return CmdResult(rc, "active" if rc == 0 else "failed")
        raise AssertionError(argv)


@pytest.fixture
def env(tmp_path):
    etc = tmp_path / "etc-haproxy"
    etc.mkdir()
    (etc / "haproxy.cfg").write_text(ORIGINAL)
    (etc / "kunde").write_text("alt.example.de\n")
    cfg = AppConfig(
        database=tmp_path / "db.sqlite",
        haproxy_cfg=etc / "haproxy.cfg",
        lists_dir=etc,
        backup_dir=etc / "backup",
        haproxy_bin="haproxy",
        reload_cmd=["sudo", "-n", "systemctl", "reload", "haproxy"],
        is_active_cmd=["systemctl", "is-active", "haproxy"],
    )
    return cfg, etc


@pytest.fixture
def db(env, state):
    cfg, _ = env
    Session = make_sessionmaker(cfg.database)
    with Session() as s:
        load_state(s, state)
        s.commit()
        yield s


def test_successful_apply(env, db):
    cfg, etc = env
    runner = FakeRunner()
    result = apply_current(db, Applier(cfg, runner), "Erstes Anwenden")
    assert result.ok, result.message
    text = (etc / "haproxy.cfg").read_text()
    assert "backend server_141_SSL" in text
    # Listenpfade in der temporären Prüf-Datei zeigen auf das Temp-Verzeichnis …
    assert "-i -f " in runner.checked_cfg and f"-i -f {etc}/" not in runner.checked_cfg
    # … in der installierten Datei auf das echte Verzeichnis
    assert f"-i -f {etc}/kunde" in text
    assert (etc / "kunde").read_text() == "kunde.example.org\nwww.kunde.example.org\n"
    assert (etc / "allweb").read_text() == "allweb.example.net\n"
    # Sicherung der alten Dateien
    assert (result.backup_dir / "haproxy.cfg").read_text() == ORIGINAL
    assert (result.backup_dir / "kunde").read_text() == "alt.example.de\n"
    # Reihenfolge der Befehle: Prüfung, Reload (kein Restart), Status
    assert [c[-2:] for c in runner.calls] == [runner.calls[0][-2:], ["reload", "haproxy"], ["is-active", "haproxy"]]
    assert not any("restart" in c for c in runner.calls)
    # Fassung gespeichert, mit Datenstand
    v = db.get(Version, result.version_id)
    assert v.cfg_text == text and v.description == "Erstes Anwenden"
    assert json.loads(v.state_json) == export_state(db)
    assert not list(etc.glob(".*haproxy-ui-*"))  # keine halben Dateien übrig


def test_failed_check_changes_nothing(env, db):
    cfg, etc = env
    runner = FakeRunner(check_ok=False)
    result = apply_current(db, Applier(cfg, runner), "x")
    assert not result.ok and result.stage == "check"
    assert "unknown keyword 'bogus'" in result.report.haproxy_output
    assert (etc / "haproxy.cfg").read_text() == ORIGINAL
    assert (etc / "kunde").read_text() == "alt.example.de\n"
    assert not (etc / "backup").exists()
    assert not any("reload" in c for c in runner.calls)
    assert db.query(Version).count() == 0


def test_own_check_failure_blocks_apply(env, db):
    cfg, etc = env
    svc = db.query(Service).filter_by(name="server_121").one()
    svc.domains = "seafile.example.de"  # gehört schon server_141
    db.commit()
    result = apply_current(db, Applier(cfg, FakeRunner()), "x")
    assert not result.ok
    assert any("seafile.example.de" in e for e in result.report.errors)
    assert (etc / "haproxy.cfg").read_text() == ORIGINAL


def test_failed_reload_restores_previous(env, db):
    cfg, etc = env
    runner = FakeRunner(reload_results=[1, 0])
    result = apply_current(db, Applier(cfg, runner), "x")
    assert not result.ok and result.stage == "reload"
    assert (etc / "haproxy.cfg").read_text() == ORIGINAL
    assert (etc / "kunde").read_text() == "alt.example.de\n"
    assert not (etc / "allweb").exists()  # neu angelegte Liste wieder entfernt
    assert sum("reload" in c for c in runner.calls) == 2  # zweites Laden mit alter Fassung
    assert any("erfolgreich" in d for d in result.details)
    assert db.query(Version).count() == 0


def test_inactive_after_reload_restores_previous(env, db):
    cfg, etc = env
    result = apply_current(db, Applier(cfg, FakeRunner(active_results=[3, 0])), "x")
    assert not result.ok and result.stage == "reload"
    assert (etc / "haproxy.cfg").read_text() == ORIGINAL


def test_own_checks(state):
    assert own_checks(state) == []
    state["services"][2]["enabled"] = True
    state["domain_lists"][0]["domains"] = []
    errs = own_checks(state)
    assert any("mailurlhttp ist leer" in e for e in errs)
    state["services"].append(dict(state["services"][3]))
    assert any("mehrfach vergeben" in e for e in own_checks(state))


def test_restore_and_discard(env, db):
    cfg, etc = env
    runner = FakeRunner()
    first = apply_current(db, Applier(cfg, runner), "eins")
    first_text = (etc / "haproxy.cfg").read_text()

    db.query(Service).filter_by(name="server_121").one().http_port = 8081
    db.commit()
    second = apply_current(db, Applier(cfg, runner), "zwei")
    assert second.ok
    assert "10.0.0.21:8081" in (etc / "haproxy.cfg").read_text()

    # Verwerfen setzt auf die letzte angewendete Fassung zurück
    db.query(Service).filter_by(name="server_121").one().http_port = 9999
    db.commit()
    assert discard_changes(db)
    assert db.query(Service).filter_by(name="server_121").one().http_port == 8081
    assert pending_notes(db) == []

    # Wiederherstellen der ersten Fassung
    res = restore_version(db, Applier(cfg, runner), first.version_id)
    assert res.ok
    assert (etc / "haproxy.cfg").read_text() == first_text
    assert db.query(Service).filter_by(name="server_121").one().http_port == 80
    assert db.query(Version).count() == 3


def test_failed_restore_keeps_database(env, db):
    cfg, etc = env
    apply_current(db, Applier(cfg, FakeRunner()), "eins")
    db.query(Service).filter_by(name="server_121").one().http_port = 8081
    db.commit()
    v2 = apply_current(db, Applier(cfg, FakeRunner()), "zwei")
    res = restore_version(db, Applier(cfg, FakeRunner(check_ok=False)), v2.version_id - 1)
    assert not res.ok
    assert db.query(Service).filter_by(name="server_121").one().http_port == 8081


def test_record_version(db, state):
    v = record_version(db, state, "cfg", {"a": "x\n"}, "")
    assert v.description == "Ohne Beschreibung"
