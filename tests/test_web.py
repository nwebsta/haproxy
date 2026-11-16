from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from haproxy_ui import auth
from haproxy_ui.apply import record_version
from haproxy_ui.config import AppConfig
from haproxy_ui.models import Service
from haproxy_ui.proxyproto import Attempt, TestReport
from haproxy_ui.state import load_state
from haproxy_ui.web import create_app

from .test_apply import ORIGINAL, FakeRunner

PASSWORD = "richtig-langes-passwort"


@pytest.fixture
def app_env(tmp_path, state):
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "haproxy.cfg").write_text(ORIGINAL)
    cfg = AppConfig(
        database=tmp_path / "db.sqlite", haproxy_cfg=etc / "haproxy.cfg", lists_dir=etc,
        backup_dir=etc / "backup", haproxy_bin="haproxy",
        reload_cmd=["systemctl", "reload", "haproxy"], is_active_cmd=["systemctl", "is-active", "haproxy"],
        max_failed_logins=3,
    )
    calls = []

    def tester(ip, port, side, domain, configured):
        calls.append((ip, port, side, domain, configured))
        return TestReport(side, ip, port, domain, configured,
                          [Attempt("off", False, "400"), Attempt("v1", True, "200"), Attempt("v2", False, "x")])

    runner = FakeRunner()
    app = create_app(cfg, runner=runner, target_tester=tester)
    with app.state.Session() as db:
        load_state(db, state)
        record_version(db, state, ORIGINAL, {}, "Import")
        auth.set_admin(db, "admin", PASSWORD)
    return app, cfg, etc, calls, runner


@pytest.fixture
def client(app_env):
    return TestClient(app_env[0], base_url="http://127.0.0.1")


def login(client, password=PASSWORD):
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    return client.post("/login", data={"username": "admin", "password": password, "csrf_token": token},
                       follow_redirects=False)


def csrf_of(client) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get("/services").text).group(1)


@pytest.mark.parametrize("path", ["/", "/services", "/services/1", "/services/new", "/lists", "/lists/1",
                                  "/history", "/history/1", "/config", "/review", "/gibtsnicht"])
def test_no_page_without_login(client, path):
    r = client.get(path, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_post_without_login(client):
    r = client.post("/services/1/toggle", follow_redirects=False)
    assert r.status_code == 303
    r = client.post("/services/1/toggle", headers={"HX-Request": "true"}, follow_redirects=False)
    assert r.status_code == 401 and r.headers["HX-Redirect"] == "/login"


def test_login_page_and_cookie_flags(client):
    assert client.get("/login").status_code == 200
    r = login(client)
    assert r.status_code == 303
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie.replace("Strict", "strict")
    assert client.get("/services").status_code == 200


def test_wrong_password_and_lockout(client):
    for _ in range(3):
        assert login(client, "falsch").status_code == 401
    r = login(client)  # richtiges Passwort, aber gesperrt
    assert r.status_code == 429 and "gesperrt" in r.text


def test_login_requires_login_csrf(client):
    client.get("/login")
    r = client.post("/login", data={"username": "admin", "password": PASSWORD, "csrf_token": "x"})
    assert r.status_code == 403


def test_csrf_required_on_writes(client):
    login(client)
    r = client.post("/services/1/toggle", follow_redirects=False)
    assert r.status_code == 403
    r = client.post("/services/1/toggle", headers={"X-CSRF-Token": "falsch"}, follow_redirects=False)
    assert r.status_code == 403
    r = client.post("/services/1/toggle", headers={"X-CSRF-Token": csrf_of(client)}, follow_redirects=False)
    assert r.status_code == 303


def test_overview_shows_both_proxy_values(client):
    login(client)
    html = client.get("/services").text
    row = html[html.index(">server_141<"):]
    row = row[: row.index("</tr>")]
    assert '<span class="mono">80</span> <span class="px px-off"' in row
    assert '<span class="mono">443</span> <span class="px px-v1"' in row
    # Deaktivierte Dienste stehen abgesetzt am Ende
    assert html.index("Deaktiviert (3)") > html.index(">server_121<")
    assert html.index(">server_142<") > html.index("Deaktiviert (3)")


def test_create_service_defaults_and_independent_sides(client, app_env):
    login(client)
    csrf = csrf_of(client)
    form = {"csrf_token": csrf, "name": "neu_1", "target_ip": "10.0.0.9", "domain_mode": "direct",
            "domains": "neu.example.de", "http_port": "80", "http_proxy": "off",
            "https_port": "443", "https_proxy": "v2", "enabled": "on"}
    r = client.post("/services/new", data=form, follow_redirects=False)
    assert r.status_code == 303, r.text
    with app_env[0].state.Session() as db:
        s = db.query(Service).filter_by(name="neu_1").one()
        assert (s.http_proxy, s.https_proxy) == ("off", "v2")
    # neues Formular startet beidseitig mit "aus"
    html = client.get("/services/new").text
    assert html.count('value="off" checked') == 2


def test_create_service_rejects_bad_input(client):
    login(client)
    form = {"csrf_token": csrf_of(client), "name": "neu\nbackend x", "target_ip": "10.0.0.9 ",
            "domain_mode": "direct", "domains": "seafile.example.de", "http_port": "0",
            "http_proxy": "v3", "https_port": "443", "https_proxy": "off", "enabled": "on"}
    r = client.post("/services/new", data=form)
    assert r.status_code == 422
    for msg in ("Name:", "IP-Adresse", "Port:", "PROXY-Modus"):
        assert msg in r.text


def test_domain_conflict_on_save(client):
    login(client)
    form = {"csrf_token": csrf_of(client), "name": "doppelt", "target_ip": "10.0.0.9",
            "domain_mode": "direct", "domains": "seafile.example.de", "http_port": "80",
            "http_proxy": "off", "https_port": "443", "https_proxy": "off", "enabled": "on"}
    r = client.post("/services/new", data=form)
    assert r.status_code == 422 and "server_141" in r.text


def test_toggle_htmx_returns_table(client, app_env):
    login(client)
    r = client.post("/services/3/toggle", headers={"X-CSRF-Token": csrf_of(client), "HX-Request": "true"})
    assert r.status_code == 200
    assert 'id="service-table"' in r.text and 'hx-swap-oob="true"' in r.text


def test_target_test_uses_stored_service_and_changes_nothing(client, app_env):
    login(client)
    with app_env[0].state.Session() as db:
        svc = db.query(Service).filter_by(name="server_141").one()
        sid, before = svc.id, (svc.http_proxy, svc.https_proxy)
    r = client.post(f"/services/{sid}/test/https", headers={"X-CSRF-Token": csrf_of(client)},
                    data={"target_ip": "8.8.8.8"})
    assert r.status_code == 200
    assert app_env[3] == [("10.0.0.41", 443, "https", "seafile.example.de", "v1")]
    assert r.text.count('<li class=') == 3 and "passt." in r.text
    with app_env[0].state.Session() as db:
        svc = db.get(Service, sid)
        assert (svc.http_proxy, svc.https_proxy) == before


def test_review_and_apply(client, app_env):
    _, cfg, etc, _, runner = app_env
    login(client)
    html = client.get("/review").text
    assert "Anwenden und neu laden" in html and "d-add" in html
    r = client.post("/review/apply", data={"csrf_token": csrf_of(client), "description": "Erstes Anwenden"})
    assert r.status_code == 200 and "Angewendet" in r.text
    assert "backend server_141_SSL" in (etc / "haproxy.cfg").read_text()
    assert "Erstes Anwenden" in client.get("/history").text


def test_review_blocks_apply_on_failed_check(client, app_env):
    app_env[4].check_ok = False
    login(client)
    html = client.get("/review").text
    assert "unknown keyword" in html
    assert re.search(r'<button type="submit" class="btn btn-primary" disabled', html)
    r = client.post("/review/apply", data={"csrf_token": csrf_of(client)})
    assert "Nicht angewendet" in r.text
    assert (app_env[2] / "haproxy.cfg").read_text() == ORIGINAL


def test_all_pages_render(client):
    login(client)
    for path in ["/services", "/services/1", "/services/new", "/lists", "/lists/1",
                 "/history", "/history/1", "/config", "/review"]:
        r = client.get(path)
        assert r.status_code == 200, path
        assert "Content-Security-Policy" in r.headers


def test_lists_crud(client):
    login(client)
    csrf = csrf_of(client)
    r = client.post("/lists", data={"csrf_token": csrf, "name": "neue", "domains": "x.example.de\ny.example.de"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert "neue" in client.get("/lists").text
    r = client.post("/lists", data={"csrf_token": csrf, "name": "../x", "domains": ""})
    assert r.status_code == 422
    # benutzte Liste lässt sich nicht löschen
    r = client.post("/lists/1/delete", data={"csrf_token": csrf})
    assert r.status_code == 409
