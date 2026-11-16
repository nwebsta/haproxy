from __future__ import annotations

from pathlib import Path

import pytest

from haproxy_ui.config import AppConfig, load_config


def test_defaults_listen_local_without_tls():
    c = AppConfig()
    assert c.listen_host == "127.0.0.1" and c.listen_port == 8765
    assert not c.tls_enabled and c.cookie_secure is False


def test_example_config_loads():
    c = load_config(Path(__file__).parent.parent / "deploy" / "config.example.toml")
    assert c.listen_host == "127.0.0.1" and not c.tls_enabled


def test_tls_enables_secure_cookie(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('listen_host = "0.0.0.0"\nlisten_port = 9443\ntls_cert = "/a/cert.pem"\ntls_key = "/a/key.pem"\n')
    c = load_config(p)
    assert c.tls_enabled and c.cookie_secure
    assert c.tls_cert == Path("/a/cert.pem") and c.listen_port == 9443


def test_tls_needs_cert_and_key(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('tls_cert = "/a/cert.pem"\n')
    with pytest.raises(ValueError, match="gemeinsam"):
        load_config(p)


def test_unknown_key_rejected(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("lisen_port = 1\n")
    with pytest.raises(ValueError, match="Unbekannter Schlüssel"):
        load_config(p)
