from __future__ import annotations

import pytest
from pydantic import ValidationError

from haproxy_ui.validation import (
    InvalidInput,
    ServiceIn,
    check_domain,
    check_ipv4,
    check_list_name,
    check_port,
    check_proxy_mode,
    check_service_name,
    normalize_head,
    parse_domain_lines,
    pydantic_errors,
)


@pytest.mark.parametrize("v", ["server_141", "a", "abc_123", "x" * 64])
def test_service_name_ok(v):
    assert check_service_name(v) == v


@pytest.mark.parametrize(
    "v", ["", "Server", "a-b", "a b", "a\nb", "x" * 65, "http_in", "ä", "a;b", "name\r"]
)
def test_service_name_bad(v):
    with pytest.raises(InvalidInput):
        check_service_name(v)


@pytest.mark.parametrize("v", ["mailurlhttp", "kunde", "all-web_2"])
def test_list_name_ok(v):
    assert check_list_name(v) == v


@pytest.mark.parametrize("v", ["haproxy.cfg", "../etc", "errors", "backup", "-x", "a/b", "a b", ""])
def test_list_name_bad(v):
    with pytest.raises(InvalidInput):
        check_list_name(v)


def test_ipv4():
    assert check_ipv4("10.0.0.41") == "10.0.0.41"
    for bad in ["256.1.1.1", "1.2.3", "01.2.3.4", "1.2.3.4 ", " 1.2.3.4", "::1", "1.2.3.4\n", "a.b.c.d", ""]:
        with pytest.raises(InvalidInput):
            check_ipv4(bad)


def test_port():
    assert check_port("80") == 80
    assert check_port(65535) == 65535
    for bad in ["0", "65536", "-1", "8080 ", "1e3", "", True, None, 70000]:
        with pytest.raises(InvalidInput):
            check_port(bad)


def test_domain():
    assert check_domain("Seafile.Example.DE") == "seafile.example.de"
    assert check_domain("a-b.c1.example") == "a-b.c1.example"
    for bad in [
        "localhost", "-a.de", "a-.de", "a..de", "a.de.", "*.example.de", "a b.de",
        "a.de\nbackend x", "ä.de", "a_b.de", "1.2.3.4", "x" * 64 + ".de", "",
    ]:
        with pytest.raises(InvalidInput):
            check_domain(bad)


def test_domain_lines():
    assert parse_domain_lines("a.example.de\n\n  b.example.de  \n") == ["a.example.de", "b.example.de"]
    assert parse_domain_lines("# x\na.de", allow_comments=True) == ["a.de"]
    with pytest.raises(InvalidInput, match="Zeile 2"):
        parse_domain_lines("a.de\nb c.de")
    with pytest.raises(InvalidInput, match="doppelt"):
        parse_domain_lines("a.de\nA.de")


def test_proxy_mode():
    for v in ("off", "v1", "v2"):
        assert check_proxy_mode(v) == v
    for bad in ("", "on", "send-proxy", "V1"):
        with pytest.raises(InvalidInput):
            check_proxy_mode(bad)


def test_head():
    assert normalize_head("global\r\n  daemon  \r\n\r\n") == "global\n  daemon"
    with pytest.raises(InvalidInput):
        normalize_head("  \n ")


def _svc(**kw):
    base = dict(name="svc", target_ip="10.0.0.1", domains="a.example.de", http_port="80", https_port="443")
    base.update(kw)
    return base


def test_service_model_ok():
    s = ServiceIn.model_validate(_svc())
    assert s.http_proxy == "off" and s.https_proxy == "off"  # neue Dienste: PROXY aus
    assert s.domains == ["a.example.de"]


def test_service_model_errors_are_german():
    with pytest.raises(ValidationError) as ei:
        ServiceIn.model_validate(_svc(name="A B", http_port="99999", target_ip="1.2.3"))
    errs = pydantic_errors(ei.value)
    assert set(errs) == {"name", "http_port", "target_ip"}
    assert errs["http_port"].startswith("Port:")


def test_service_needs_domains_xor_list():
    with pytest.raises(ValidationError):
        ServiceIn.model_validate(_svc(domains=""))
    with pytest.raises(ValidationError):
        ServiceIn.model_validate(_svc(domain_list="kunde"))
    assert ServiceIn.model_validate(_svc(domains="", domain_list="kunde")).domain_list == "kunde"
