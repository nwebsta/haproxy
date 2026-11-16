from __future__ import annotations

import pytest

from haproxy_ui.importer import CfgImportError, parse_cfg

from .conftest import FIXTURES

# Tabelle aus der Bauanweisung:
# name: (domains | Liste, ip, http_port, http_proxy, https_port, https_proxy, redirect, enabled)
EXPECTED = {
    "server_141": (["seafile.example.de"], "10.0.0.41", 80, "off", 443, "v1", False, True),
    "server_151": ("mailurlhttp", "10.0.0.51", 8080, "off", 8443, "off", True, True),
    "server_152": ("kunde", "10.0.0.152", 80, "v1", 443, "v1", False, True),
    "server_103": (["updatedns.example.de"], "10.0.0.3", 80, "off", 443, "v1", False, True),
    "server_121": (["kq.example.de"], "10.0.0.21", 80, "v1", 443, "v1", False, True),
    "server_142": (["nextcloud.example.de"], "10.0.0.42", 80, "v2", 443, "v2", False, False),
    "server_109": (["amp.example.de"], "10.0.0.9", 80, "v1", 443, "v1", False, False),
    "server_102": ("allweb", "10.0.0.2", 80, "v2", 443, "v2", False, False),
}


def test_import_yields_exactly_the_eight_services(imported):
    services = {s["name"]: s for s in imported.state["services"]}
    assert set(services) == set(EXPECTED)
    for name, (doms, ip, hp, hpx, sp, spx, redirect, enabled) in EXPECTED.items():
        s = services[name]
        if isinstance(doms, str):
            assert s["domain_list"] == doms and s["domains"] == []
        else:
            assert s["domains"] == doms and s["domain_list"] is None
        assert (s["target_ip"], s["http_port"], s["http_proxy"]) == (ip, hp, hpx), name
        assert (s["https_port"], s["https_proxy"]) == (sp, spx), name
        assert s["redirect_to_https"] is redirect, name
        assert s["enabled"] is enabled, name
        # ssl-hello-chk ohne check ist wirkungslos -> Health-Check aus
        assert s["health_check"] is False, name


def test_import_head_and_bind(imported):
    st = imported.state
    assert st["bind_ip"] == "203.0.113.10"
    assert st["head"].startswith("global\n\tlog /dev/log\tlocal0")
    assert "defaults" in st["head"]
    assert st["head"].rstrip().endswith("errorfile 504 /etc/haproxy/errors/504.http")
    assert "frontend" not in st["head"]


def test_import_domain_lists(imported):
    lists = {l["name"]: l["domains"] for l in imported.state["domain_lists"]}
    assert lists["mailurlhttp"] == [
        "mail.example.de", "webmail.example.de", "autoconfig.example.de"
    ]
    assert lists["kunde"] == ["kunde.example.org", "www.kunde.example.org"]
    assert set(imported.raw_lists) == {"mailurlhttp", "kunde", "allweb"}


def test_missing_list_of_disabled_service_warns(original_cfg, tmp_path):
    for name in ("mailurlhttp", "kunde"):
        (tmp_path / name).write_text((FIXTURES / name).read_text())
    res = parse_cfg(original_cfg, read_dir=tmp_path)
    assert any("allweb" in w for w in res.warnings)
    assert {"name": "allweb", "domains": []} in res.state["domain_lists"]


def test_missing_list_of_active_service_aborts(original_cfg, tmp_path):
    (tmp_path / "mailurlhttp").write_text("a.example.de\n")
    with pytest.raises(CfgImportError) as ei:
        parse_cfg(original_cfg, read_dir=tmp_path)
    assert "kunde" in str(ei.value)
    assert ei.value.lineno == _line_of(original_cfg, "acl acl_152 hdr(host)")


def _line_of(text: str, needle: str) -> int:
    for no, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return no
    raise AssertionError(needle)


@pytest.mark.parametrize(
    "old,new,needle",
    [
        # unbekannte Direktive im Frontend
        ("        option forwardfor\n" if False else "\toption forwardfor\n",
         "\toption forwardfor\n\ttimeout client 5s\n", "timeout client 5s"),
        # unbekannte server-Option
        ("server server1 10.0.0.21:80 send-proxy\n",
         "server server1 10.0.0.21:80 send-proxy weight 10\n", "weight 10"),
        # gemischt: ACL aktiv, use_backend auskommentiert
        ("\tuse_backend server_103 if acl_103\n", "\t#use_backend server_103 if acl_103\n",
         "#use_backend server_103 if acl_103"),
        # unbekanntes Frontend
        ("frontend https_in\n", "frontend stats\n", "frontend stats"),
        # ungültige IP
        ("10.0.0.3:80\n", "10.0.0.300:80\n", "10.0.0.300:80"),
        # auskommentierte Prosa im Frontend
        ("  bind 203.0.113.10:443\n", "  bind 203.0.113.10:443\n  # irgendwas\n", "# irgendwas"),
    ],
)
def test_unknown_constructs_abort_with_line_number(original_cfg, old, new, needle):
    assert old in original_cfg
    text = original_cfg.replace(old, new, 1)
    with pytest.raises(CfgImportError) as ei:
        parse_cfg(text, read_dir=FIXTURES)
    assert ei.value.lineno == _line_of(text, needle)


def test_domains_must_match_on_both_sides(original_cfg):
    text = original_cfg.replace(
        "acl acl_121 req.ssl_sni -i kq.example.de", "acl acl_121 req.ssl_sni -i kq2.example.de"
    )
    with pytest.raises(CfgImportError, match="unterscheiden sich"):
        parse_cfg(text, read_dir=FIXTURES)


def test_unused_backend_aborts(original_cfg):
    text = original_cfg + "\nbackend extra\n    mode http\n    server s 10.0.0.1:80\n"
    with pytest.raises(CfgImportError) as ei:
        parse_cfg(text, read_dir=FIXTURES)
    assert ei.value.lineno == _line_of(text, "backend extra")


def test_health_check_imported_when_check_set(original_cfg):
    text = original_cfg.replace(
        "server server1 10.0.0.21:80 send-proxy\n", "server server1 10.0.0.21:80 send-proxy check\n"
    ).replace(
        "server server1 10.0.0.21:443 send-proxy\n", "server server1 10.0.0.21:443 send-proxy check\n"
    )
    res = parse_cfg(text, read_dir=FIXTURES)
    svc = next(s for s in res.state["services"] if s["name"] == "server_121")
    assert svc["health_check"] is True
