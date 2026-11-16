"""Einmaliger Import einer bestehenden haproxy.cfg.

Der Import versteht nur das Muster der Ausgangsdatei:
  * Kopfbereich aus global/defaults (wird wörtlich übernommen)
  * frontend http_in  (mode http, ACLs per hdr(host), use_backend, optional Umleitung)
  * frontend https_in (mode tcp, ACLs per req.ssl_sni, use_backend)
  * je Dienst ein Backend <name> und <name>_SSL mit genau einer server-Zeile
Auskommentierte ACL-/use_backend-Zeilen ergeben deaktivierte Dienste.
Alles andere führt zum Abbruch mit Zeilennummer – es wird nie geraten.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .validation import (
    InvalidInput,
    check_domain,
    check_ipv4,
    check_list_name,
    check_port,
    check_service_name,
    parse_domain_lines,
)

SECTION_KEYWORDS = {
    "global", "defaults", "frontend", "backend", "listen", "resolvers", "peers",
    "userlist", "mailers", "program", "http-errors", "ring", "cache", "fcgi-app",
}
GENERATED_MARKER = "# Diese Datei wird von haproxy-ui erzeugt."


class CfgImportError(Exception):
    def __init__(self, lineno: int, message: str):
        self.lineno = lineno
        self.message = message
        super().__init__(f"Zeile {lineno}: {message}")


@dataclass
class _Line:
    no: int
    text: str  # ohne Einrückung und ohne führendes '#'
    commented: bool

    @property
    def tokens(self) -> list[str]:
        return self.text.split()


@dataclass
class _Section:
    keyword: str
    name: str | None
    no: int
    lines: list[_Line] = field(default_factory=list)


@dataclass
class _Acl:
    no: int
    commented: bool
    kind: str  # "direct" | "list"
    values: tuple[str, ...]  # Domains oder (Listenname,)
    used: bool = False


@dataclass
class _UseBackend:
    no: int
    commented: bool
    backend: str
    acl: str
    used: bool = False


@dataclass
class _Backend:
    no: int
    name: str
    mode: str | None = None
    ssl_hello_chk: bool = False
    server: tuple[str, int, str, bool] | None = None  # ip, port, proxy, check
    used: bool = False


@dataclass
class ImportResult:
    state: dict
    raw_lists: dict[str, str]
    warnings: list[str]


def _split_sections(text: str) -> tuple[list[_Section], list[str]]:
    lines = text.splitlines()
    sections: list[_Section] = []
    current: _Section | None = None
    for no, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if not stripped:
            continue
        if raw[0] not in " \t" and not stripped.startswith("#"):
            tokens = stripped.split()
            if tokens[0] in SECTION_KEYWORDS:
                current = _Section(tokens[0], tokens[1] if len(tokens) > 1 else None, no)
                sections.append(current)
                continue
        if current is None:
            if stripped.startswith("#"):
                continue
            raise CfgImportError(no, "Zeile steht außerhalb eines Abschnitts")
        commented = stripped.startswith("#")
        content = stripped.lstrip("#").strip() if commented else stripped
        current.lines.append(_Line(no, content, commented))
    return sections, lines


def _parse_acl_values(line: _Line, rest: list[str], cfg_lists_dir: str) -> tuple[str, tuple[str, ...]]:
    if not rest:
        raise CfgImportError(line.no, "ACL ohne Domains")
    if rest[0] == "-f":
        if len(rest) != 2:
            raise CfgImportError(line.no, "nach -f wird genau ein Dateipfad erwartet")
        path = PurePosixPath(rest[1])
        if str(path.parent) != cfg_lists_dir:
            raise CfgImportError(
                line.no, f"Domainliste {path} liegt nicht in {cfg_lists_dir}"
            )
        try:
            name = check_list_name(path.name)
        except InvalidInput as exc:
            raise CfgImportError(line.no, str(exc)) from None
        return "list", (name,)
    domains = []
    for tok in rest:
        if tok.startswith("-"):
            raise CfgImportError(line.no, f"Option {tok} wird nicht unterstützt")
        try:
            domains.append(check_domain(tok))
        except InvalidInput as exc:
            raise CfgImportError(line.no, str(exc)) from None
    return "direct", tuple(domains)


def _bind(line: _Line, port: int) -> str:
    toks = line.tokens
    if len(toks) != 2 or ":" not in toks[1]:
        raise CfgImportError(line.no, "bind-Zeile wird nicht verstanden (erwartet: bind <IP>:<Port>)")
    ip, _, p = toks[1].rpartition(":")
    try:
        ip = check_ipv4(ip)
    except InvalidInput as exc:
        raise CfgImportError(line.no, str(exc)) from None
    if p != str(port):
        raise CfgImportError(line.no, f"bind-Port {p} erwartet {port}")
    return ip


def _parse_frontend(sec: _Section, http: bool, cfg_lists_dir: str):
    acls: dict[str, _Acl] = {}
    uses: list[_UseBackend] = []
    redirects: list[tuple[int, bool, str]] = []
    bind_ip = None
    if http:
        required = {("mode", "http"), ("option", "httplog"), ("option", "forwardfor")}
        match_fetch = "hdr(host)"
    else:
        required = {
            ("mode", "tcp"), ("option", "tcplog"),
            ("acl", "tls", "req.ssl_hello_type", "1"),
            ("tcp-request", "inspect-delay", "5s"),
            ("tcp-request", "content", "accept", "if", "tls"),
        }
        match_fetch = "req.ssl_sni"
    seen: set[tuple[str, ...]] = set()

    for line in sec.lines:
        toks = line.tokens
        key = tuple(toks)
        if line.commented and toks[0] not in ("acl", "use_backend", "http-request"):
            raise CfgImportError(line.no, "auskommentierte Zeile kann nicht zugeordnet werden")
        if key in required and not line.commented:
            if key in seen:
                raise CfgImportError(line.no, "Zeile steht doppelt")
            seen.add(key)
        elif toks[0] == "bind" and not line.commented:
            if bind_ip is not None:
                raise CfgImportError(line.no, "mehrere bind-Zeilen werden nicht unterstützt")
            bind_ip = _bind(line, 80 if http else 443)
        elif toks[0] == "acl" and len(toks) >= 4 and toks[2] == match_fetch and toks[3] == "-i":
            name = toks[1]
            if name in acls or name == "tls":
                raise CfgImportError(line.no, f"ACL {name} ist doppelt definiert")
            kind, values = _parse_acl_values(line, toks[4:], cfg_lists_dir)
            acls[name] = _Acl(line.no, line.commented, kind, values)
        elif len(toks) == 4 and toks[0] == "use_backend" and toks[2] == "if":
            uses.append(_UseBackend(line.no, line.commented, toks[1], toks[3]))
        elif http and toks[:5] == ["http-request", "redirect", "scheme", "https", "if"] and len(toks) == 6:
            redirects.append((line.no, line.commented, toks[5]))
        else:
            raise CfgImportError(line.no, f"Zeile in frontend {sec.name} wird nicht verstanden")

    missing = required - seen
    if missing:
        raise CfgImportError(sec.no, f"frontend {sec.name}: es fehlt „{' '.join(sorted(missing)[0])}“")
    if bind_ip is None:
        raise CfgImportError(sec.no, f"frontend {sec.name}: bind-Zeile fehlt")
    return acls, uses, redirects, bind_ip


def _parse_backend(sec: _Section) -> _Backend:
    be = _Backend(sec.no, sec.name or "")
    for line in sec.lines:
        toks = line.tokens
        if line.commented:
            raise CfgImportError(line.no, "auskommentierte Zeile im Backend wird nicht verstanden")
        if toks[0] == "mode" and len(toks) == 2 and toks[1] in ("http", "tcp") and be.mode is None:
            be.mode = toks[1]
        elif toks == ["option", "ssl-hello-chk"] and not be.ssl_hello_chk:
            be.ssl_hello_chk = True
        elif toks[0] == "server" and len(toks) >= 3:
            if be.server is not None:
                raise CfgImportError(line.no, "mehrere server-Zeilen pro Backend werden nicht unterstützt")
            ip, _, port = toks[2].rpartition(":")
            try:
                ip = check_ipv4(ip)
                port_n = check_port(port)
            except InvalidInput as exc:
                raise CfgImportError(line.no, str(exc)) from None
            proxy, check = "off", False
            for opt in toks[3:]:
                if opt == "send-proxy" and proxy == "off":
                    proxy = "v1"
                elif opt == "send-proxy-v2" and proxy == "off":
                    proxy = "v2"
                elif opt == "check" and not check:
                    check = True
                else:
                    raise CfgImportError(line.no, f"server-Option „{opt}“ wird nicht unterstützt")
            be.server = (ip, port_n, proxy, check)
        else:
            raise CfgImportError(line.no, f"Zeile in backend {be.name} wird nicht verstanden")
    if be.mode is None:
        raise CfgImportError(sec.no, f"backend {be.name}: mode fehlt")
    if be.server is None:
        raise CfgImportError(sec.no, f"backend {be.name}: server-Zeile fehlt")
    return be


def _read_list(path: Path, name: str) -> tuple[str, list[str]]:
    raw = path.read_text(encoding="utf-8")
    try:
        return raw, parse_domain_lines(raw, allow_comments=True)
    except InvalidInput as exc:
        raise CfgImportError(0, f"Domainliste {path}: {exc}") from None


def parse_cfg(text: str, *, cfg_lists_dir: str = "/etc/haproxy", read_dir: Path | None = None) -> ImportResult:
    """Liest eine haproxy.cfg. `read_dir` ist das Verzeichnis, aus dem die Domainlisten gelesen werden."""
    sections, lines = _split_sections(text)
    if not sections:
        raise CfgImportError(1, "keine Abschnitte gefunden")

    # Kopfbereich: alles vor dem ersten frontend/backend
    first_proxy = next((i for i, s in enumerate(sections) if s.keyword not in ("global", "defaults")), None)
    if first_proxy is None:
        raise CfgImportError(len(lines), "keine frontend-/backend-Abschnitte gefunden")
    head_secs = sections[:first_proxy]
    if not head_secs:
        raise CfgImportError(sections[0].no, "Abschnitte global/defaults fehlen")
    head_lines = lines[: sections[first_proxy].no - 1]
    # Kommentar, den der Generator selbst schreibt, nicht in den Kopf übernehmen
    if any(GENERATED_MARKER in l for l in head_lines):
        start = next(i for i, l in enumerate(head_lines) if l.strip() and not l.startswith("#"))
        head_lines = head_lines[start:]
    head = "\n".join(l.rstrip() for l in head_lines).strip("\n")

    frontends: dict[str, _Section] = {}
    backends: dict[str, _Backend] = {}
    for sec in sections[first_proxy:]:
        if sec.keyword == "frontend":
            if sec.name not in ("http_in", "https_in"):
                raise CfgImportError(sec.no, f"frontend {sec.name} wird nicht unterstützt (nur http_in und https_in)")
            if sec.name in frontends:
                raise CfgImportError(sec.no, f"frontend {sec.name} ist doppelt")
            frontends[sec.name] = sec
        elif sec.keyword == "backend":
            if not sec.name:
                raise CfgImportError(sec.no, "backend ohne Namen")
            if sec.name in backends:
                raise CfgImportError(sec.no, f"backend {sec.name} ist doppelt")
            backends[sec.name] = _parse_backend(sec)
        else:
            raise CfgImportError(sec.no, f"Abschnitt {sec.keyword} wird hier nicht unterstützt")
    for name in ("http_in", "https_in"):
        if name not in frontends:
            raise CfgImportError(len(lines), f"frontend {name} fehlt")

    h_acls, h_uses, redirects, h_bind = _parse_frontend(frontends["http_in"], True, cfg_lists_dir)
    s_acls, s_uses, _, s_bind = _parse_frontend(frontends["https_in"], False, cfg_lists_dir)
    if h_bind != s_bind:
        raise CfgImportError(frontends["https_in"].no, "http_in und https_in haben unterschiedliche bind-Adressen")

    s_uses_by_backend: dict[str, _UseBackend] = {}
    for u in s_uses:
        if u.backend in s_uses_by_backend:
            raise CfgImportError(u.no, f"use_backend {u.backend} steht doppelt")
        s_uses_by_backend[u.backend] = u

    services: list[dict] = []
    list_refs: dict[str, tuple[int, list[bool]]] = {}  # name -> (erste Zeile, [aktiv?...])
    seen_backends: set[str] = set()

    for u in h_uses:
        if u.backend in seen_backends:
            raise CfgImportError(u.no, f"use_backend {u.backend} steht doppelt")
        seen_backends.add(u.backend)
        try:
            name = check_service_name(u.backend)
        except InvalidInput as exc:
            raise CfgImportError(u.no, f"Backend-Name ergibt keinen gültigen Dienstnamen: {exc}") from None
        acl = h_acls.get(u.acl)
        if acl is None:
            raise CfgImportError(u.no, f"ACL {u.acl} ist in http_in nicht definiert")
        if acl.commented != u.commented:
            raise CfgImportError(u.no, f"ACL {u.acl} und use_backend sind nicht beide aktiv bzw. auskommentiert")
        acl.used = True
        be = backends.get(name)
        if be is None:
            raise CfgImportError(u.no, f"backend {name} fehlt")
        if be.mode != "http":
            raise CfgImportError(be.no, f"backend {name}: mode http erwartet")
        be.used = True

        su = s_uses_by_backend.get(f"{name}_SSL")
        if su is None:
            raise CfgImportError(u.no, f"in https_in fehlt „use_backend {name}_SSL“")
        su.used = True
        sacl = s_acls.get(su.acl)
        if sacl is None:
            raise CfgImportError(su.no, f"ACL {su.acl} ist in https_in nicht definiert")
        sacl.used = True
        if not (sacl.commented == su.commented == u.commented):
            raise CfgImportError(su.no, f"Dienst {name}: HTTP- und HTTPS-Seite sind nicht gleich aktiv/auskommentiert")
        if (sacl.kind, sacl.values) != (acl.kind, acl.values):
            raise CfgImportError(sacl.no, f"Dienst {name}: Domains von HTTP- und HTTPS-Seite unterscheiden sich")
        sbe = backends.get(f"{name}_SSL")
        if sbe is None:
            raise CfgImportError(su.no, f"backend {name}_SSL fehlt")
        if sbe.mode != "tcp":
            raise CfgImportError(sbe.no, f"backend {name}_SSL: mode tcp erwartet")
        sbe.used = True

        h_ip, h_port, h_proxy, h_check = be.server
        s_ip, s_port, s_proxy, s_check = sbe.server
        if h_ip != s_ip:
            raise CfgImportError(sbe.no, f"Dienst {name}: HTTP- und HTTPS-Backend haben unterschiedliche Ziel-IPs")
        if h_check != s_check:
            raise CfgImportError(sbe.no, f"Dienst {name}: check ist nur auf einer Seite gesetzt")

        enabled = not u.commented
        redirect = False
        for r_no, r_commented, r_acl in redirects:
            if r_acl != u.acl:
                continue
            if r_commented and enabled:
                raise CfgImportError(r_no, "auskommentierte Umleitung bei aktivem Dienst ist nicht eindeutig")
            if not r_commented and not enabled:
                raise CfgImportError(r_no, "Umleitung verweist auf eine auskommentierte ACL")
            redirect = True

        svc = {
            "name": name,
            "enabled": enabled,
            "domains": list(acl.values) if acl.kind == "direct" else [],
            "domain_list": acl.values[0] if acl.kind == "list" else None,
            "target_ip": h_ip,
            "http_port": h_port,
            "http_proxy": h_proxy,
            "https_port": s_port,
            "https_proxy": s_proxy,
            "redirect_to_https": redirect,
            # ssl-hello-chk ohne "check" ist wirkungslos und wird nicht übernommen
            "health_check": h_check,
        }
        services.append(svc)
        if acl.kind == "list":
            first_no, flags = list_refs.setdefault(acl.values[0], (acl.no, []))
            flags.append(enabled)

    for r_no, _, r_acl in redirects:
        if r_acl not in h_acls or not h_acls[r_acl].used:
            raise CfgImportError(r_no, f"Umleitung verweist auf unbekannte ACL {r_acl}")
    for name, a in h_acls.items():
        if not a.used:
            raise CfgImportError(a.no, f"ACL {name} wird von keinem use_backend benutzt")
    for name, a in s_acls.items():
        if not a.used:
            raise CfgImportError(a.no, f"ACL {name} wird von keinem use_backend benutzt")
    for u in s_uses:
        if not u.used:
            raise CfgImportError(u.no, f"use_backend {u.backend} hat kein Gegenstück in http_in")
    for be in backends.values():
        if not be.used:
            raise CfgImportError(be.no, f"backend {be.name} wird keinem Dienst zugeordnet")

    # Domainlisten einlesen
    read_dir = Path(read_dir) if read_dir else Path(cfg_lists_dir)
    warnings: list[str] = []
    raw_lists: dict[str, str] = {}
    domain_lists: list[dict] = []
    for lname, (first_no, flags) in list_refs.items():
        path = read_dir / lname
        if not path.is_file():
            if any(flags):
                raise CfgImportError(first_no, f"Domainliste {path} nicht gefunden")
            warnings.append(
                f"Domainliste {path} nicht gefunden; nur von deaktivierten Diensten benutzt – leer angelegt."
            )
            domain_lists.append({"name": lname, "domains": []})
            continue
        try:
            raw, domains = _read_list(path, lname)
        except CfgImportError as exc:
            raise CfgImportError(first_no, exc.message) from None
        if not domains and any(flags):
            raise CfgImportError(first_no, f"Domainliste {path} ist leer")
        raw_lists[lname] = raw
        domain_lists.append({"name": lname, "domains": domains})

    state = {
        "bind_ip": h_bind,
        "head": head,
        "domain_lists": domain_lists,
        "services": services,
    }
    return ImportResult(state=state, raw_lists=raw_lists, warnings=warnings)
