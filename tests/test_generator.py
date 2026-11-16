from __future__ import annotations

import re

import pytest

from haproxy_ui.generator import render, server_line
from haproxy_ui.importer import parse_cfg
from haproxy_ui.validation import InvalidInput

from .conftest import FIXTURES


def _routing(state: dict) -> dict:
    """Wirkung einer cfg: aktive Dienste mit Domains, Zielen und PROXY-Werten."""
    out = {}
    for s in state["services"]:
        if not s["enabled"]:
            continue
        out[s["name"]] = (
            tuple(s["domains"]), s["domain_list"], s["target_ip"],
            s["http_port"], s["http_proxy"], s["https_port"], s["https_proxy"],
            s["redirect_to_https"], s["health_check"],
        )
    return out


def test_generated_cfg_has_same_effect_as_original(imported):
    out = render(imported.state, "/etc/haproxy")
    reparsed = parse_cfg(out.cfg, read_dir=FIXTURES)
    assert _routing(reparsed.state) == _routing(imported.state)
    assert len(_routing(reparsed.state)) == 5
    assert reparsed.state["bind_ip"] == "203.0.113.10"
    assert reparsed.state["head"] == imported.state["head"]  # Generator-Kommentar wird nicht übernommen


def test_expected_lines(state):
    cfg = render(state, "/etc/haproxy").cfg
    for line in [
        "    bind 203.0.113.10:80",
        "    bind 203.0.113.10:443",
        "    acl acl_server_141 hdr(host) -i seafile.example.de",
        "    acl acl_server_141 req.ssl_sni -i seafile.example.de",
        "    acl acl_server_151 hdr(host) -i -f /etc/haproxy/mailurlhttp",
        "    http-request redirect scheme https if acl_server_151",
        "    use_backend server_152_SSL if acl_server_152",
        "    server server1 10.0.0.41:80",
        "    server server1 10.0.0.41:443 send-proxy",
        "    server server1 10.0.0.51:8080",
        "    server server1 10.0.0.51:8443",
        "    server server1 10.0.0.152:80 send-proxy",
        "    acl tls req.ssl_hello_type 1",
        "    tcp-request inspect-delay 5s",
        "    tcp-request content accept if tls",
    ]:
        assert line in cfg.splitlines(), line
    # ohne Health-Check keine wirkungslose Option
    assert "ssl-hello-chk" not in cfg
    # deaktivierte Dienste stehen nicht in der Datei
    for name in ("server_142", "server_109", "server_102", "allweb", "nextcloud"):
        assert name not in cfg


def test_header_comment_and_indentation(state):
    cfg = render(state, "/etc/haproxy").cfg
    assert cfg.startswith("# ----")
    assert "Handänderungen gehen beim nächsten Anwenden verloren" in cfg.splitlines()[2]
    generated = cfg[cfg.index("frontend http_in"):]
    for line in generated.splitlines():
        if line and not re.match(r"(frontend|backend) ", line):
            assert line.startswith("    ") and not line.startswith("     "), repr(line)
            assert "\t" not in line


def test_head_is_verbatim(state):
    cfg = render(state, "/etc/haproxy").cfg
    assert state["head"] in cfg
    assert "\tlog /dev/log\tlocal0" in cfg


def test_proxy_v2_and_health_check(state):
    svc = next(s for s in state["services"] if s["name"] == "server_142")
    svc["enabled"] = True
    svc["health_check"] = True
    cfg = render(state, "/etc/haproxy").cfg
    assert "    server server1 10.0.0.42:80 send-proxy-v2 check" in cfg
    block = cfg[cfg.index("\nbackend server_142_SSL") + 1:].split("\n\n")[0]
    assert block.splitlines() == [
        "backend server_142_SSL",
        "    mode tcp",
        "    option ssl-hello-chk",
        "    server server1 10.0.0.42:443 send-proxy-v2 check",
    ]


def test_multiple_domains_and_list_dir(state):
    svc = next(s for s in state["services"] if s["name"] == "server_141")
    svc["domains"] = ["seafile.example.de", "files.example.de"]
    out = render(state, "/tmp/xyz")
    assert "    acl acl_server_141 hdr(host) -i seafile.example.de files.example.de" in out.cfg
    assert "-i -f /tmp/xyz/mailurlhttp" in out.cfg
    assert out.lists["kunde"] == "kunde.example.org\nwww.kunde.example.org\n"


def test_server_line():
    assert server_line("10.0.0.1", 80, "off", False) == "server server1 10.0.0.1:80"
    assert server_line("10.0.0.1", 443, "v1", True) == "server server1 10.0.0.1:443 send-proxy check"
    assert server_line("10.0.0.1", 443, "v2", False) == "server server1 10.0.0.1:443 send-proxy-v2"


@pytest.mark.parametrize(
    "field,value",
    [
        ("target_ip", "10.0.0.1\n    server evil 1.2.3.4:80"),
        ("name", "x\nbackend evil"),
        ("domains", ["ok.example.de evil"]),
        ("http_proxy", "send-proxy"),
        ("https_port", 0),
    ],
)
def test_render_rejects_injected_values(state, field, value):
    state["services"][2][field] = value
    with pytest.raises(InvalidInput):
        render(state, "/etc/haproxy")


def test_no_services(state):
    state["services"] = []
    cfg = render(state, "/etc/haproxy").cfg
    assert "use_backend" not in cfg
    assert "frontend https_in" in cfg
