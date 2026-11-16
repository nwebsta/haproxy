from __future__ import annotations

import socket
import threading

import pytest

from haproxy_ui.proxyproto import V2_SIGNATURE, Attempt, attempt, build_v1, build_v2, test_target


def test_v1_header():
    assert build_v1("192.168.1.5", "10.0.0.41", 51234, 443) == (
        b"PROXY TCP4 192.168.1.5 10.0.0.41 51234 443\r\n"
    )


def test_v2_header_bytes():
    h = build_v2("192.168.1.5", "10.0.0.41", 51234, 443)
    assert h == bytes.fromhex(
        "0d0a0d0a000d0a515549540a"  # Signatur, 12 Byte
        "21"  # Version 2, Befehl PROXY
        "11"  # TCP über IPv4
        "000c"  # Länge 12
        "c0a80105"  # 192.168.1.5
        "0a000029"  # 10.0.0.41
        "c822"  # 51234
        "01bb"  # 443
    )
    assert h[:12] == V2_SIGNATURE and len(V2_SIGNATURE) == 12
    assert len(h) == 28


@pytest.mark.parametrize("args", [("::1", "1.2.3.4", 1, 2), ("1.2.3.4", "1.2.3", 1, 2), ("1.2.3.4", "1.2.3.4", 70000, 1)])
def test_headers_reject_bad_input(args):
    with pytest.raises(ValueError):
        build_v1(*args)
    with pytest.raises(ValueError):
        build_v2(*args)


class FakeTarget:
    """Lokaler HTTP-Server, der nur einen bestimmten PROXY-Modus akzeptiert."""

    def __init__(self, expects: str):
        self.expects = expects
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.seen: list[bytes] = []
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            conn.settimeout(2)
            data = b""
            try:
                # Bis zum Ende der HTTP-Anfrage lesen. Die v2-Signatur beginnt selbst
                # mit \r\n\r\n, daher erst ab "GET" nach dem Leerzeilen-Ende suchen.
                while b"GET" not in data or b"\r\n\r\n" not in data[data.find(b"GET"):]:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    data += chunk
            except OSError:
                return
            self.seen.append(data)
            if data.startswith(V2_SIGNATURE):
                mode = "v2"
            elif data.startswith(b"PROXY TCP4 "):
                mode = "v1"
            else:
                mode = "off"
            status = b"200 OK" if mode == self.expects else b"400 Bad Request"
            conn.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Length: 0\r\n\r\n")

    def close(self):
        self._stop = True
        self.sock.close()


@pytest.mark.parametrize("expects", ["off", "v1", "v2"])
def test_http_target_test_detects_mode(expects):
    target = FakeTarget(expects)
    try:
        report = test_target("127.0.0.1", target.port, "http", "app.example.de", configured="v1", timeout=2)
    finally:
        target.close()
    assert [a.mode for a in report.attempts] == ["off", "v1", "v2"]
    assert report.working == [expects]
    assert report.kind == "one"
    assert report.matches is (expects == "v1")
    assert ("passt NICHT" in report.verdict) is (expects != "v1")
    assert all(b"Host: app.example.de\r\n" in d for d in target.seen)


def test_unreachable_target():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # Port ist jetzt geschlossen
    report = test_target("127.0.0.1", port, "https", "app.example.de", configured="off", timeout=1)
    assert report.kind == "none" and report.matches is None
    assert "nicht erreichbar" in report.verdict
    assert all("Verbindung fehlgeschlagen" in a.detail for a in report.attempts)


def test_https_tls_failure_against_plain_http():
    target = FakeTarget("off")
    try:
        a = attempt("127.0.0.1", target.port, "https", "app.example.de", "off", timeout=2)
    finally:
        target.close()
    assert not a.ok


def test_several_modes_work():
    fake = lambda ip, port, side, domain, mode, timeout: Attempt(mode, mode in ("off", "v1"), "x")
    r = test_target("10.0.0.1", 443, "https", "a.example.de", "v2", attempt_fn=fake)
    assert r.kind == "many" and r.working == ["off", "v1"]
    assert r.matches is False
    assert "wahlweise" in r.verdict
