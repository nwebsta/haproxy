# haproxy-ui

Schlanke Weboberfläche, mit der ein Administrator **einen** HAProxy auf Debian verwaltet.
Statt ACLs und Backends von Hand zu schreiben, pflegt man „Dienste“; die Oberfläche erzeugt
daraus die vollständige `haproxy.cfg`, prüft sie mit `haproxy -c` und lädt HAProxy neu.

- Ein Eingang (IPv4) auf Port 80 und 443
- `http_in` verteilt nach Host-Header, `https_in` nach SNI (TLS wird durchgereicht, nicht terminiert)
- PROXY-Protokoll (aus / v1 / v2) pro Dienst **getrennt für HTTP und HTTPS**, mit eingebautem Zieltest
- Domains direkt oder als Domainliste (`-f /etc/haproxy/<liste>`)
- Änderungen erst prüfen (Diff + `haproxy -c`), dann anwenden; automatisches Zurückrollen bei
  fehlgeschlagenem Reload; Änderungsverlauf mit Wiederherstellen

Technik: Python 3.11+, FastAPI, Jinja2 + HTMX, SQLite. Kein Node, kein Docker, kein Build-Schritt.

## Installation (Debian 12)

Voraussetzung: HAProxy ist installiert (`apt install haproxy`) und läuft.

```bash
git clone https://github.com/nwebsta/haproxy.git haproxy-ui
cd haproxy-ui
sudo ./install.sh
```

Ohne Optionen fragt das Skript bei der Erstinstallation nach Adresse, Port und HTTPS.
Alles lässt sich auch direkt angeben:

| Option | Bedeutung |
| --- | --- |
| `--listen ADRESSE` | Adresse der Oberfläche: `127.0.0.1` (Voreinstellung, nur lokal), eine bestimmte IP des Servers oder `0.0.0.0` für alle |
| `--port PORT` | Port der Oberfläche (Voreinstellung `8765`) |
| `--tls self-signed` | HTTPS mit selbst erzeugtem Zertifikat (`/etc/haproxy-ui/tls/`, 825 Tage gültig, wird bei Updates weiterverwendet) |
| `--tls-cert DATEI --tls-key DATEI` | HTTPS mit vorhandenem Zertifikat, z. B. von Let's Encrypt; der Benutzer `haproxy-ui` muss beide Dateien lesen können |
| `--tls none` | unverschlüsselt – nur sinnvoll mit `127.0.0.1` und SSH-Tunnel |
| `--yes` | keine Rückfragen (Voreinstellungen) |

Beispiel: Oberfläche auf der internen IP, Port 9443, mit eigenem Zertifikat:

```bash
sudo ./install.sh --listen 10.0.0.5 --port 9443 --tls self-signed
```

Bei `self-signed` gibt das Skript den SHA-256-Fingerabdruck aus. Der Browser warnt beim ersten
Aufruf; vergleiche den Fingerabdruck und lass die Ausnahme dann zu. Bei einem Update ändert das
Skript Adresse, Port und HTTPS nur, wenn die Option ausdrücklich angegeben ist.

`install.sh` erledigt:

| Schritt | Ergebnis |
| --- | --- |
| Pakete | `python3-venv`, `sudo` falls nötig |
| Benutzer | Systembenutzer `haproxy-ui` (kein Login, nicht root) |
| Programm | `/opt/haproxy-ui/app`, Python-Umgebung `/opt/haproxy-ui/venv` (feste Versionen aus `requirements.txt`) |
| Daten | Datenbank unter `/var/lib/haproxy-ui/` |
| Konfiguration | `/etc/haproxy-ui/config.toml` (wird nur angelegt, nie überschrieben) |
| Rechte | Gruppe `haproxy-ui` darf in `/etc/haproxy/` schreiben; `/etc/haproxy/backup/` wird angelegt |
| sudo | `/etc/sudoers.d/haproxy-ui` erlaubt genau `systemctl reload haproxy` |
| Dienst | systemd-Unit `haproxy-ui.service`, aktiviert und gestartet |

Danach einmalig:

```bash
# 1. bestehende haproxy.cfg importieren (Dienste, Domainlisten, Kopfbereich)
sudo -u haproxy-ui HAPROXY_UI_CONFIG=/etc/haproxy-ui/config.toml /opt/haproxy-ui/venv/bin/haproxy-ui import-cfg

# 2. Admin-Konto anlegen (fragt das Passwort ab, mind. 12 Zeichen)
sudo -u haproxy-ui HAPROXY_UI_CONFIG=/etc/haproxy-ui/config.toml /opt/haproxy-ui/venv/bin/haproxy-ui create-admin
```

Der Import ändert nichts an HAProxy. Er läuft nur bei leerer Datenbank und bricht bei allem, was er
nicht eindeutig zuordnen kann, mit Zeilennummer ab. Auskommentierte ACL-/`use_backend`-Zeilen werden
zu deaktivierten Diensten. Domainlisten werden aus dem Verzeichnis der cfg gelesen
(`--lists-dir` zum Ändern).

### Zugriff

In der Voreinstellung lauscht die Oberfläche nur auf `127.0.0.1:8765`. Zugriff per SSH-Tunnel:

```bash
ssh -L 8765:127.0.0.1:8765 root@haproxy-host
# dann im Browser: http://127.0.0.1:8765/
```

Lauscht sie auf einer anderen Adresse, dann nur mit HTTPS und möglichst nur aus dem internen
Netz bzw. per Firewall auf die eigene Admin-IP beschränkt. Ohne HTTPS gehen Passwort und
Sitzung im Klartext übers Netz; das Skript warnt in diesem Fall.

Adresse, Port und Zertifikat stehen in `/etc/haproxy-ui/config.toml`
(`listen_host`, `listen_port`, `tls_cert`, `tls_key`); nach einer Änderung
`sudo systemctl restart haproxy-ui`.

Die Oberfläche **nie** über den verwalteten HAProxy veröffentlichen.

### Update

Entweder im vorhandenen Klon:

```bash
cd haproxy-ui
git pull
sudo ./install.sh
```

oder mit einem frischen Klon – der alte Klon wird nicht gebraucht und kann gelöscht werden:

```bash
git clone https://github.com/nwebsta/haproxy.git /tmp/haproxy-ui
sudo /tmp/haproxy-ui/install.sh
rm -rf /tmp/haproxy-ui
```

Beides ist gleichwertig: `install.sh` kopiert das Programm aus dem Verzeichnis, in dem es liegt,
nach `/opt/haproxy-ui/`. Datenbank (`/var/lib/haproxy-ui/`), Konfiguration
(`/etc/haproxy-ui/`) und Zertifikat liegen außerhalb des Klons und bleiben erhalten. Das Skript
erkennt ein Update daran, dass `/opt/haproxy-ui/venv` schon existiert, und fragt dann nichts ab.

Beim Update hält das Skript den Dienst an, sichert die Datenbank nach
`/var/lib/haproxy-ui/db-backup/` (die letzten 10 bleiben), ersetzt die Programmdateien,
aktualisiert die Abhängigkeiten und startet neu. `config.toml` und Datenbank bleiben erhalten.

### Passwort zurücksetzen

`create-admin` erneut ausführen. Das setzt das Passwort neu und beendet alle Sitzungen.

## Bedienung

1. **Dienste**: Übersicht mit Ziel-IP, HTTP- und HTTPS-Port samt PROXY-Wert, Schalter aktiv/deaktiviert.
2. **Dienst bearbeiten**: Speichern schreibt nur in die Datenbank – die laufende Konfiguration bleibt
   unberührt. „Ziel testen“ prüft vom HAProxy-Host aus, ob das Ziel ohne PROXY-Kopf, mit v1 oder mit
   v2 antwortet (je 3 s), und zeigt, ob die Einstellung passt. Der Test ändert nie etwas.
3. **Änderungen prüfen**: Zeilenweiser Unterschied, eigene Prüfungen (Domain-Dubletten, leere oder
   fehlende Listen, Namen) und `haproxy -c`. „Anwenden und neu laden“ ist gesperrt, solange eine
   Prüfung fehlschlägt.

Ablauf beim Anwenden: temporär schreiben → prüfen → alte Dateien nach
`/etc/haproxy/backup/<Zeitstempel>/` sichern → neue Dateien per Umbenennen einsetzen →
`systemctl reload haproxy` → `systemctl is-active haproxy`. Schlägt Reload oder Statusprüfung fehl,
wird die Sicherung zurückgespielt und erneut geladen.

Die `haproxy.cfg` wird bei jedem Anwenden vollständig neu geschrieben. Handänderungen gehen dabei
verloren; den Kopfbereich (`global`/`defaults`) bearbeitet man unter „haproxy.cfg ansehen“.

### Erzeugte Konfiguration

Pro aktivem Dienst `name`:

```
acl acl_name hdr(host) -i a.example.de b.example.de      # in http_in
acl acl_name req.ssl_sni -i a.example.de b.example.de    # in https_in
backend name        →  server server1 <ip>:<http_port>  [send-proxy|send-proxy-v2] [check]
backend name_SSL    →  server server1 <ip>:<https_port> [send-proxy|send-proxy-v2] [check]
```

Mit „Erreichbarkeit laufend prüfen“ bekommen beide `server`-Zeilen `check`, das HTTPS-Backend
zusätzlich `option ssl-hello-chk`. Ist PROXY gesetzt, schickt HAProxy den Kopf auch bei den Checks mit.

## Sicherheit

- Anmeldung immer nötig; Passwort als Argon2-Hash; serverseitige Sitzung, Cookie mit `HttpOnly`
  und `SameSite=Strict`; CSRF-Token auf allen schreibenden Anfragen; Sperre nach 5 Fehlversuchen
  für 15 Minuten (einstellbar).
- Läuft als eigener Benutzer, nicht als root. sudo nur für `systemctl reload haproxy`.
- Alle Eingaben werden streng geprüft (Namen, IPv4, Ports, Hostnamen); Leerzeichen und
  Zeilenumbrüche werden abgelehnt. Der Kopfbereich ist das einzige Freitextfeld und wird nur durch
  `haproxy -c` geprüft.
- Externe Befehle nur als Argumentliste, nie über eine Shell.
- Der Zieltest verbindet sich nur mit IP und Port eines gespeicherten Dienstes.
- Content-Security-Policy ohne Inline-Skripte; HTMX liegt lokal bei (`haproxy_ui/static/htmx.min.js`, 2.0.4).

## Entwicklung

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt -e .
.venv/bin/python -m pytest
```

Die Tests brauchen keinen installierten HAProxy: `haproxy -c` und `systemctl` werden durch einen
Testersatz simuliert. Die Domainlisten unter `tests/fixtures/` sind erfundene Testdaten.

Lokal starten mit eigener Konfiguration (z. B. `reload_cmd = ["/bin/true"]` und Pfaden in einem
Arbeitsverzeichnis):

```bash
HAPROXY_UI_CONFIG=./dev-data/config.toml .venv/bin/haproxy-ui serve
```

### Aufbau

```
haproxy_ui/
  config.py        Konfigurationsdatei (TOML)
  models.py, db.py SQLite über SQLAlchemy
  validation.py    Eingabeprüfung (Pydantic + eigene Regeln)
  state.py         Datenstand als dict (Grundlage für Erzeugung und Fassungen)
  importer.py      einmaliger Import einer bestehenden haproxy.cfg
  generator.py     Erzeugung (templates_cfg/haproxy.cfg.j2)
  apply.py         Prüfen, Anwenden, Zurückrollen, Verlauf
  proxyproto.py    PROXY-Köpfe v1/v2 und Zieltest
  auth.py          Anmeldung, Sitzungen, Sperre
  web.py           FastAPI-Routen
  cli.py           import-cfg | create-admin | serve
deploy/            systemd-Unit, sudoers-Regel, Beispielkonfiguration
install.sh         Installation und Update
```

## Nicht enthalten

Zertifikatsverwaltung, mehrere HAProxy-Server, mehrere Ziele pro Dienst, Statistiken,
mehrere Benutzer oder Rollen.
