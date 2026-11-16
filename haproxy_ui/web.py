"""FastAPI-Anwendung: Routen, Anmeldung, CSRF-Schutz."""

from __future__ import annotations

import difflib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import auth, proxyproto
from .apply import (
    Applier,
    add_pending_note,
    apply_current,
    discard_changes,
    latest_version,
    pending_notes,
    restore_version,
)
from .config import AppConfig
from .db import get_setting, make_sessionmaker, set_setting
from .generator import render
from .models import DomainList, Service, Version
from .state import export_state
from .validation import (
    PROXY_LABELS,
    DomainListIn,
    InvalidInput,
    ServiceIn,
    check_ipv4,
    normalize_head,
    parse_domain_lines,
    pydantic_errors,
)

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=BASE / "templates")
templates.env.globals["PROXY_LABELS"] = PROXY_LABELS
templates.env.globals["PROXY_LONG"] = {"off": "aus", "v1": "v1 (send-proxy)", "v2": "v2 (send-proxy-v2)"}


def _localtime(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.replace(tzinfo=timezone.utc).astimezone().strftime("%d.%m.%Y %H:%M:%S")


templates.env.filters["localtime"] = _localtime

PUBLIC_PATHS = {"/login"}
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'"
)


# -- Infrastruktur -----------------------------------------------------------------


def get_db(request: Request):
    with request.app.state.Session() as db:
        yield db


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unbekannt"


async def auth_middleware(request: Request, call_next):
    path = request.url.path
    request.state.csrf = None
    if path in PUBLIC_PATHS or path.startswith("/static/"):
        response = await call_next(request)
    else:
        token = request.cookies.get(auth.SESSION_COOKIE)
        with request.app.state.Session() as db:
            sess = auth.get_session(db, token)
            csrf = sess.csrf_token if sess else None
        if csrf is None:
            if request.headers.get("HX-Request"):
                response = Response(status_code=401, headers={"HX-Redirect": "/login"})
            else:
                response = RedirectResponse("/login", status_code=303)
        else:
            request.state.csrf = csrf
            response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if not path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store"
    return response


async def csrf_protect(request: Request) -> None:
    """Prüft das CSRF-Token bei allen schreibenden Anfragen."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    sent = request.headers.get("X-CSRF-Token")
    if not sent:
        form = await request.form()
        sent = form.get("csrf_token")
    if not auth.tokens_equal(sent if isinstance(sent, str) else None, request.state.csrf):
        raise HTTPException(403, "CSRF-Prüfung fehlgeschlagen. Bitte Seite neu laden.")


def _disk_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return ""


def has_pending(request: Request, db: Session) -> bool:
    config: AppConfig = request.app.state.config
    try:
        rendered = render(export_state(db), config.lists_dir)
    except InvalidInput:
        return True
    if rendered.cfg != _disk_text(config.haproxy_cfg):
        return True
    return any(text != _disk_text(config.lists_dir / name) for name, text in rendered.lists.items())


def page(request: Request, db: Session, name: str, nav: str = "", status_code: int = 200, **ctx):
    ctx.update(csrf=request.state.csrf, pending=has_pending(request, db), nav=nav)
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


public = APIRouter()
private = APIRouter(dependencies=[Depends(csrf_protect)])


# -- Anmeldung ----------------------------------------------------------------------


def _login_page(request: Request, error: str = "", status_code: int = 200):
    token = secrets.token_urlsafe(32)
    resp = templates.TemplateResponse(
        request, "login.html", {"login_csrf": token, "error": error}, status_code=status_code
    )
    resp.set_cookie(
        auth.LOGIN_CSRF_COOKIE, token, httponly=True, samesite="strict",
        secure=request.app.state.config.cookie_secure, path="/login", max_age=3600,
    )
    return resp


@public.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    return _login_page(request)


@public.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    config: AppConfig = request.app.state.config
    form = await request.form()
    if not auth.tokens_equal(form.get("csrf_token"), request.cookies.get(auth.LOGIN_CSRF_COOKIE)):
        return _login_page(request, "Sitzung abgelaufen, bitte erneut versuchen.", 403)
    ip = _client_ip(request)
    until = auth.locked_until(db, ip)
    if until:
        return _login_page(
            request, f"Zu viele Fehlversuche. Anmeldung gesperrt bis {_localtime(until)}.", 429
        )
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))
    ok = await run_in_threadpool(auth.verify_login, db, username, password)
    if not ok:
        auth.register_failure(db, ip, config)
        return _login_page(request, "Benutzername oder Passwort falsch.", 401)
    auth.reset_failures(db, ip)
    token = auth.create_session(db, config)
    resp = _redirect("/services")
    resp.set_cookie(
        auth.SESSION_COOKIE, token, httponly=True, samesite="strict",
        secure=config.cookie_secure, path="/", max_age=config.session_hours * 3600,
    )
    resp.delete_cookie(auth.LOGIN_CSRF_COOKIE, path="/login")
    return resp


@private.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    auth.destroy_session(db, request.cookies.get(auth.SESSION_COOKIE))
    resp = _redirect("/login")
    resp.delete_cookie(auth.SESSION_COOKIE, path="/")
    return resp


# -- Dienste ------------------------------------------------------------------------


def _all_services(db: Session) -> tuple[list[Service], list[Service]]:
    services = db.scalars(select(Service).order_by(Service.id)).all()
    return [s for s in services if s.enabled], [s for s in services if not s.enabled]


def _lists(db: Session) -> list[DomainList]:
    return db.scalars(select(DomainList).order_by(DomainList.name)).all()


@private.get("/")
async def index():
    return _redirect("/services")


@private.get("/services", response_class=HTMLResponse)
async def services_page(request: Request, db: Session = Depends(get_db)):
    active, inactive = _all_services(db)
    return page(request, db, "services.html", "services", active=active, inactive=inactive)


def _get_service(db: Session, service_id: int) -> Service:
    svc = db.get(Service, service_id)
    if svc is None:
        raise HTTPException(404, "Dienst nicht gefunden")
    return svc


def _service_values(svc: Service | None) -> dict:
    if svc is None:
        return {
            "name": "", "target_ip": "", "domain_mode": "direct", "domains": "", "domain_list": "",
            "http_port": "80", "http_proxy": "off", "https_port": "443", "https_proxy": "off",
            "redirect_to_https": False, "health_check": False, "enabled": True,
        }
    return {
        "name": svc.name, "target_ip": svc.target_ip,
        "domain_mode": "list" if svc.domain_list else "direct",
        "domains": "\n".join(svc.domain_items),
        "domain_list": svc.domain_list.name if svc.domain_list else "",
        "http_port": str(svc.http_port), "http_proxy": svc.http_proxy,
        "https_port": str(svc.https_port), "https_proxy": svc.https_proxy,
        "redirect_to_https": svc.redirect_to_https, "health_check": svc.health_check,
        "enabled": svc.enabled,
    }


def _form_values(form) -> dict:
    mode = "list" if form.get("domain_mode") == "list" else "direct"
    return {
        "name": str(form.get("name", "")),
        "target_ip": str(form.get("target_ip", "")),
        "domain_mode": mode,
        "domains": str(form.get("domains", "")),
        "domain_list": str(form.get("domain_list", "")),
        "http_port": str(form.get("http_port", "")),
        "http_proxy": str(form.get("http_proxy", "")),
        "https_port": str(form.get("https_port", "")),
        "https_proxy": str(form.get("https_proxy", "")),
        "redirect_to_https": form.get("redirect_to_https") == "on",
        "health_check": form.get("health_check") == "on",
        "enabled": form.get("enabled") == "on",
    }


def _validate_service(db: Session, values: dict, current: Service | None):
    data = dict(values)
    mode = data.pop("domain_mode")
    if mode == "list":
        data["domains"] = ""
    else:
        data["domain_list"] = None
    errors: dict[str, str] = {}
    try:
        svc_in = ServiceIn.model_validate(data)
    except ValidationError as exc:
        return None, None, pydantic_errors(exc)

    other = db.scalars(select(Service).where(Service.name == svc_in.name)).first()
    if other is not None and other is not current:
        errors["name"] = f"Name {svc_in.name} ist bereits vergeben"
    lst = None
    domains = svc_in.domains
    if svc_in.domain_list:
        lst = db.scalars(select(DomainList).where(DomainList.name == svc_in.domain_list)).first()
        if lst is None:
            errors["domain_list"] = "Domainliste existiert nicht"
        else:
            domains = lst.domain_items
    if svc_in.enabled and not errors:
        mine = set(domains)
        for s in db.scalars(select(Service).where(Service.enabled.is_(True))).all():
            if s is current:
                continue
            clash = mine & set(s.effective_domains)
            if clash:
                field = "domain_list" if lst else "domains"
                errors[field] = f"{', '.join(sorted(clash))} gehört schon zum aktiven Dienst {s.name}"
                break
    return svc_in, lst, errors


def _apply_to_model(svc: Service, svc_in: ServiceIn, lst: DomainList | None) -> None:
    svc.name = svc_in.name
    svc.enabled = svc_in.enabled
    svc.domains = "\n".join(svc_in.domains)
    svc.domain_list = lst
    svc.target_ip = svc_in.target_ip
    svc.http_port = svc_in.http_port
    svc.http_proxy = svc_in.http_proxy
    svc.https_port = svc_in.https_port
    svc.https_proxy = svc_in.https_proxy
    svc.redirect_to_https = svc_in.redirect_to_https
    svc.health_check = svc_in.health_check


def _service_form(request, db, service, values, errors=None, status_code=200):
    return page(
        request, db, "service_form.html", "services", status_code=status_code,
        service=service, v=values, errors=errors or {}, lists=_lists(db),
    )


@private.get("/services/new", response_class=HTMLResponse)
async def service_new_form(request: Request, db: Session = Depends(get_db)):
    return _service_form(request, db, None, _service_values(None))


@private.post("/services/new")
async def service_create(request: Request, db: Session = Depends(get_db)):
    values = _form_values(await request.form())
    svc_in, lst, errors = _validate_service(db, values, None)
    if errors:
        return _service_form(request, db, None, values, errors, 422)
    svc = Service()
    _apply_to_model(svc, svc_in, lst)
    db.add(svc)
    add_pending_note(db, f"Dienst {svc.name} angelegt")
    db.commit()
    return _redirect("/services")


@private.get("/services/{service_id}", response_class=HTMLResponse)
async def service_edit_form(service_id: int, request: Request, db: Session = Depends(get_db)):
    svc = _get_service(db, service_id)
    return _service_form(request, db, svc, _service_values(svc))


@private.post("/services/{service_id}")
async def service_update(service_id: int, request: Request, db: Session = Depends(get_db)):
    svc = _get_service(db, service_id)
    values = _form_values(await request.form())
    svc_in, lst, errors = _validate_service(db, values, svc)
    if errors:
        return _service_form(request, db, svc, values, errors, 422)
    old_name = svc.name
    _apply_to_model(svc, svc_in, lst)
    add_pending_note(
        db, f"Dienst {old_name} geändert" + (f" (neuer Name {svc.name})" if old_name != svc.name else "")
    )
    db.commit()
    return _redirect("/services")


@private.post("/services/{service_id}/delete")
async def service_delete(service_id: int, db: Session = Depends(get_db)):
    svc = _get_service(db, service_id)
    add_pending_note(db, f"Dienst {svc.name} gelöscht")
    db.delete(svc)
    db.commit()
    return _redirect("/services")


@private.post("/services/{service_id}/toggle")
async def service_toggle(service_id: int, request: Request, db: Session = Depends(get_db)):
    svc = _get_service(db, service_id)
    svc.enabled = not svc.enabled
    add_pending_note(db, f"Dienst {svc.name} {'aktiviert' if svc.enabled else 'deaktiviert'}")
    db.commit()
    if request.headers.get("HX-Request"):
        active, inactive = _all_services(db)
        return templates.TemplateResponse(
            request, "_services_table.html",
            {"active": active, "inactive": inactive, "csrf": request.state.csrf,
             "pending": has_pending(request, db), "oob": True},
        )
    return _redirect("/services")


@private.post("/services/{service_id}/test/{side}", response_class=HTMLResponse)
async def service_test(service_id: int, side: str, request: Request, db: Session = Depends(get_db)):
    if side not in ("http", "https"):
        raise HTTPException(404)
    svc = _get_service(db, service_id)
    domains = svc.effective_domains
    if not domains:
        return HTMLResponse('<p class="verdict fail">Der Dienst hat keine Domain – Test nicht möglich.</p>')
    port = svc.http_port if side == "http" else svc.https_port
    configured = svc.http_proxy if side == "http" else svc.https_proxy
    tester = request.app.state.target_tester
    # Nur IP und Port des gespeicherten Dienstes – nie frei eingegebene Adressen.
    report = await run_in_threadpool(tester, svc.target_ip, port, side, domains[0], configured)
    return templates.TemplateResponse(request, "_test_result.html", {"r": report})


# -- Domainlisten ---------------------------------------------------------------------


def _get_list(db: Session, list_id: int) -> DomainList:
    lst = db.get(DomainList, list_id)
    if lst is None:
        raise HTTPException(404, "Domainliste nicht gefunden")
    return lst


@private.get("/lists", response_class=HTMLResponse)
async def lists_page(request: Request, db: Session = Depends(get_db)):
    return page(request, db, "lists.html", "lists", lists=_lists(db), v={"name": "", "domains": ""}, errors={})


@private.post("/lists")
async def list_create(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    values = {"name": str(form.get("name", "")), "domains": str(form.get("domains", ""))}
    errors: dict[str, str] = {}
    try:
        lst_in = DomainListIn.model_validate(values)
    except ValidationError as exc:
        errors = pydantic_errors(exc)
    else:
        if db.scalars(select(DomainList).where(DomainList.name == lst_in.name)).first():
            errors["name"] = f"Liste {lst_in.name} existiert bereits"
    if errors:
        return page(request, db, "lists.html", "lists", status_code=422, lists=_lists(db), v=values, errors=errors)
    db.add(DomainList(name=lst_in.name, domains="\n".join(lst_in.domains)))
    add_pending_note(db, f"Domainliste {lst_in.name} angelegt")
    db.commit()
    return _redirect("/lists")


@private.get("/lists/{list_id}", response_class=HTMLResponse)
async def list_edit_form(list_id: int, request: Request, db: Session = Depends(get_db)):
    lst = _get_list(db, list_id)
    return page(request, db, "list_edit.html", "lists", lst=lst, domains="\n".join(lst.domain_items), errors={})


@private.post("/lists/{list_id}")
async def list_update(list_id: int, request: Request, db: Session = Depends(get_db)):
    lst = _get_list(db, list_id)
    form = await request.form()
    text = str(form.get("domains", ""))
    try:
        domains = parse_domain_lines(text)
    except InvalidInput as exc:
        return page(request, db, "list_edit.html", "lists", status_code=422, lst=lst, domains=text,
                    errors={"domains": str(exc)})
    lst.domains = "\n".join(domains)
    add_pending_note(db, f"Domainliste {lst.name} geändert")
    db.commit()
    return _redirect("/lists")


@private.post("/lists/{list_id}/delete")
async def list_delete(list_id: int, request: Request, db: Session = Depends(get_db)):
    lst = _get_list(db, list_id)
    if lst.services:
        return page(request, db, "list_edit.html", "lists", status_code=409, lst=lst,
                    domains="\n".join(lst.domain_items),
                    errors={"_form": "Die Liste wird noch benutzt und kann nicht gelöscht werden."})
    add_pending_note(db, f"Domainliste {lst.name} gelöscht")
    db.delete(lst)
    db.commit()
    return _redirect("/lists")


# -- haproxy.cfg ansehen / Kopfbereich -------------------------------------------------


def _config_page(request, db, values=None, errors=None, status_code=200):
    config: AppConfig = request.app.state.config
    try:
        cfg_text, render_error = render(export_state(db), config.lists_dir).cfg, ""
    except InvalidInput as exc:
        cfg_text, render_error = "", str(exc)
    values = values or {"bind_ip": get_setting(db, "bind_ip"), "head": get_setting(db, "head")}
    return page(request, db, "config.html", "config", status_code=status_code, cfg_text=cfg_text,
                render_error=render_error, v=values, errors=errors or {})


@private.get("/config", response_class=HTMLResponse)
async def config_page(request: Request, db: Session = Depends(get_db)):
    return _config_page(request, db)


@private.post("/config")
async def config_save(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    values = {"bind_ip": str(form.get("bind_ip", "")), "head": str(form.get("head", ""))}
    errors = {}
    try:
        bind_ip = check_ipv4(values["bind_ip"])
    except InvalidInput as exc:
        errors["bind_ip"] = str(exc)
    try:
        head = normalize_head(values["head"])
    except InvalidInput as exc:
        errors["head"] = str(exc)
    if errors:
        return _config_page(request, db, values, errors, 422)
    if bind_ip != get_setting(db, "bind_ip"):
        set_setting(db, "bind_ip", bind_ip)
        add_pending_note(db, f"Eingangsadresse auf {bind_ip} geändert")
    if head != get_setting(db, "head"):
        set_setting(db, "head", head)
        add_pending_note(db, "Kopfbereich geändert")
    db.commit()
    return _redirect("/config")


# -- Prüfen und anwenden -------------------------------------------------------------------


def _diff(old: str, new: str, name: str) -> list[tuple[str, str]]:
    out = []
    for line in difflib.unified_diff(
        old.splitlines(), new.splitlines(), f"{name} (aktuell)", f"{name} (neu)", lineterm="", n=3
    ):
        if line.startswith(("+++", "---")):
            cls = "meta"
        elif line.startswith("@@"):
            cls = "hunk"
        elif line.startswith("+"):
            cls = "add"
        elif line.startswith("-"):
            cls = "del"
        else:
            cls = "ctx"
        out.append((cls, line))
    return out


@private.get("/review", response_class=HTMLResponse)
async def review_page(request: Request, db: Session = Depends(get_db)):
    config: AppConfig = request.app.state.config
    applier: Applier = request.app.state.applier
    report = await run_in_threadpool(applier.check, export_state(db))
    diffs = []
    if report.rendered:
        diffs.append(("haproxy.cfg", _diff(_disk_text(config.haproxy_cfg), report.rendered.cfg, "haproxy.cfg")))
        for name, text in report.rendered.lists.items():
            d = _diff(_disk_text(config.lists_dir / name), text, name)
            if d:
                diffs.append((f"Domainliste {name}", d))
    notes = pending_notes(db)
    return page(request, db, "review.html", "review", report=report, diffs=diffs, notes=notes,
                description="; ".join(notes), has_version=latest_version(db) is not None)


@private.post("/review/apply", response_class=HTMLResponse)
async def review_apply(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    description = str(form.get("description", "")).strip()[:1000] or "; ".join(pending_notes(db))
    result = await run_in_threadpool(apply_current, db, request.app.state.applier, description)
    return page(request, db, "apply_result.html", "review", result=result)


@private.post("/review/discard")
async def review_discard(db: Session = Depends(get_db)):
    discard_changes(db)
    return _redirect("/services")


# -- Änderungsverlauf ---------------------------------------------------------------------


@private.get("/history", response_class=HTMLResponse)
async def history_page(request: Request, db: Session = Depends(get_db)):
    versions = db.scalars(select(Version).order_by(Version.id.desc())).all()
    return page(request, db, "history.html", "history", versions=versions)


@private.get("/history/{version_id}", response_class=HTMLResponse)
async def history_view(version_id: int, request: Request, db: Session = Depends(get_db)):
    v = db.get(Version, version_id)
    if v is None:
        raise HTTPException(404, "Fassung nicht gefunden")
    return page(request, db, "history_view.html", "history", ver=v, lists=json.loads(v.lists_json))


@private.post("/history/{version_id}/restore", response_class=HTMLResponse)
async def history_restore(version_id: int, request: Request, db: Session = Depends(get_db)):
    if db.get(Version, version_id) is None:
        raise HTTPException(404, "Fassung nicht gefunden")
    result = await run_in_threadpool(restore_version, db, request.app.state.applier, version_id)
    return page(request, db, "apply_result.html", "history", result=result)


# -- App -------------------------------------------------------------------------------------


async def _http_error(request: Request, exc: StarletteHTTPException):
    return PlainTextResponse(str(exc.detail), status_code=exc.status_code)


def create_app(config: AppConfig, runner=None, target_tester=None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, title="haproxy-ui")
    app.state.config = config
    app.state.Session = make_sessionmaker(config.database)
    app.state.applier = Applier(config, runner)
    app.state.target_tester = target_tester or proxyproto.test_target
    app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
    app.middleware("http")(auth_middleware)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.include_router(public)
    app.include_router(private)
    return app
