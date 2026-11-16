"""PROXY-Protokoll: Köpfe v1/v2 bauen und Ziele testen.

Der Zieltest läuft auf dem HAProxy-Host, verbindet sich nur mit IP und Port
eines gespeicherten Dienstes und ändert nie eine Einstellung.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
V2_VERSION_PROXY = 0x21  # Version 2, Befehl PROXY
V2_TCP_OVER_IPV4 = 0x11  # AF_INET, STREAM
MODES = ("off", "v1", "v2")
MODE_LABELS = {"off": "ohne PROXY", "v1": "PROXY v1", "v2": "PROXY v2"}
TIMEOUT = 3.0


def _check_endpoint(ip: str, port: int) -> str:
    addr = ipaddress.IPv4Address(ip)
    if not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError(f"ungültiger Port: {port!r}")
    return str(addr)


def build_v1(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    src = _check_endpoint(src_ip, src_port)
    dst = _check_endpoint(dst_ip, dst_port)
    return f"PROXY TCP4 {src} {dst} {src_port} {dst_port}\r\n".encode("ascii")


def build_v2(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    src = ipaddress.IPv4Address(_check_endpoint(src_ip, src_port))
    dst = ipaddress.IPv4Address(_check_endpoint(dst_ip, dst_port))
    addresses = src.packed + dst.packed + struct.pack("!HH", src_port, dst_port)
    return V2_SIGNATURE + bytes([V2_VERSION_PROXY, V2_TCP_OVER_IPV4]) + struct.pack("!H", len(addresses)) + addresses


@dataclass
class Attempt:
    mode: str
    ok: bool
    detail: str

    @property
    def label(self) -> str:
        return MODE_LABELS[self.mode]


@dataclass
class TestReport:
    side: str  # http | https
    ip: str
    port: int
    domain: str
    configured: str
    attempts: list[Attempt]

    @property
    def working(self) -> list[str]:
        return [a.mode for a in self.attempts if a.ok]

    @property
    def kind(self) -> str:
        n = len(self.working)
        return "none" if n == 0 else "one" if n == 1 else "many"

    @property
    def matches(self) -> bool | None:
        if not self.working:
            return None
        return self.configured in self.working

    @property
    def verdict(self) -> str:
        cfg = MODE_LABELS[self.configured]
        w = self.working
        if not w:
            return ("Keine Variante funktioniert – das Ziel ist nicht erreichbar "
                    "oder lehnt alle drei Varianten ab.")
        if len(w) == 1:
            text = f"Nur „{MODE_LABELS[w[0]]}“ funktioniert."
        else:
            text = ("Das Ziel nimmt mehrere Varianten an ("
                    + ", ".join(MODE_LABELS[m] for m in w) + "), der Kopf ist dort wahlweise.")
        if self.matches:
            return f"{text} Die gewählte Einstellung „{cfg}“ passt."
        return f"{text} Die gewählte Einstellung „{cfg}“ passt NICHT."


class _Deadline:
    def __init__(self, seconds: float):
        self.end = time.monotonic() + seconds

    def left(self) -> float:
        rest = self.end - time.monotonic()
        if rest <= 0:
            raise TimeoutError("Zeitlimit überschritten")
        return rest


def attempt(ip: str, port: int, side: str, domain: str, mode: str, timeout: float = TIMEOUT) -> Attempt:
    deadline = _Deadline(timeout)
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except (TimeoutError, socket.timeout):
        return Attempt(mode, False, f"Verbindungsaufbau: Zeitlimit von {timeout:g} s überschritten")
    except OSError as exc:
        return Attempt(mode, False, f"Verbindung fehlgeschlagen: {exc.strerror or exc}")
    try:
        src_ip, src_port = sock.getsockname()[:2]
        if mode == "v1":
            sock.settimeout(deadline.left())
            sock.sendall(build_v1(src_ip, ip, src_port, port))
        elif mode == "v2":
            sock.settimeout(deadline.left())
            sock.sendall(build_v2(src_ip, ip, src_port, port))

        if side == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock.settimeout(deadline.left())
            tls = ctx.wrap_socket(sock, server_hostname=domain, do_handshake_on_connect=False)
            sock = tls
            tls.do_handshake()
            return Attempt(mode, True, f"TLS-Handshake erfolgreich ({tls.version()})")

        request = (
            f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: haproxy-ui-zieltest\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        sock.settimeout(deadline.left())
        sock.sendall(request)
        buf = b""
        while b"\r\n" not in buf and len(buf) < 8192:
            sock.settimeout(deadline.left())
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        status_line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        m = re.match(r"HTTP/\d(?:\.\d)? (\d{3})", status_line)
        if not m:
            if not buf:
                return Attempt(mode, False, "Keine Antwort – Verbindung vom Ziel geschlossen")
            return Attempt(mode, False, f"Keine HTTP-Antwort: {status_line[:80]!r}")
        code = int(m.group(1))
        if code == 400:
            return Attempt(mode, False, f"Ziel antwortet mit 400 (Anfrage nicht verstanden): {status_line[:80]}")
        return Attempt(mode, True, f"HTTP-Antwort: {status_line[:80]}")
    except ssl.SSLError as exc:
        return Attempt(mode, False, f"TLS-Fehler: {exc.reason or exc}")
    except (TimeoutError, socket.timeout):
        return Attempt(mode, False, f"Zeitlimit von {timeout:g} s überschritten")
    except OSError as exc:
        return Attempt(mode, False, f"Fehler: {exc.strerror or exc}")
    finally:
        try:
            sock.close()
        except OSError:
            pass


def test_target(ip: str, port: int, side: str, domain: str, configured: str,
                timeout: float = TIMEOUT, attempt_fn=attempt) -> TestReport:
    """Drei Versuche (ohne, v1, v2) parallel, je mit eigenem Zeitlimit."""
    if side not in ("http", "https"):
        raise ValueError(side)
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(attempt_fn, ip, port, side, domain, m, timeout) for m in MODES]
        attempts = [f.result() for f in futures]
    return TestReport(side, ip, port, domain, configured, attempts)


test_target.__test__ = False  # kein pytest-Test
TestReport.__test__ = False
