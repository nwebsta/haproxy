#!/usr/bin/env bash
# haproxy-ui: Installation und Update auf Debian.
#
#   Erstinstallation:  git clone <repo> haproxy-ui && cd haproxy-ui && sudo ./install.sh [Optionen]
#   Update:            cd haproxy-ui && git pull && sudo ./install.sh
#
# Optionen (alle optional; ohne Optionen wird bei der Erstinstallation nachgefragt):
#   --listen ADRESSE      Adresse der Oberfläche (Voreinstellung 127.0.0.1, alle: 0.0.0.0)
#   --port PORT           Port der Oberfläche (Voreinstellung 8765)
#   --tls self-signed     HTTPS mit selbst erzeugtem Zertifikat
#   --tls none            HTTP ohne Verschlüsselung (nur sinnvoll mit 127.0.0.1 + SSH-Tunnel)
#   --tls-cert DATEI --tls-key DATEI
#                         HTTPS mit vorhandenem Zertifikat (PEM), z. B. von Let's Encrypt
#   --yes                 keine Rückfragen
#
# Das Skript ist wiederholbar. config.toml wird nur angelegt bzw. bei ausdrücklich
# angegebenen Optionen angepasst; die Datenbank wird vor jedem Update gesichert.
set -euo pipefail

APP_USER=haproxy-ui
PREFIX=/opt/haproxy-ui
APP_DIR=$PREFIX/app
VENV=$PREFIX/venv
DATA_DIR=/var/lib/haproxy-ui
CONF_DIR=/etc/haproxy-ui
CONF=$CONF_DIR/config.toml
TLS_DIR=$CONF_DIR/tls
HAPROXY_DIR=/etc/haproxy
UNIT=/etc/systemd/system/haproxy-ui.service
SUDOERS=/etc/sudoers.d/haproxy-ui
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mWarnung:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31mFehler:\033[0m %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# --- Optionen ------------------------------------------------------------------
LISTEN="" PORT="" TLS_MODE="" TLS_CERT="" TLS_KEY="" ASSUME_YES=0
while (($#)); do
    case "$1" in
        --listen)   LISTEN="${2:?--listen braucht eine Adresse}"; shift 2 ;;
        --port)     PORT="${2:?--port braucht eine Zahl}"; shift 2 ;;
        --tls)      TLS_MODE="${2:?--tls braucht self-signed oder none}"; shift 2 ;;
        --tls-cert) TLS_CERT="${2:?}"; TLS_MODE=custom; shift 2 ;;
        --tls-key)  TLS_KEY="${2:?}"; TLS_MODE=custom; shift 2 ;;
        --yes|-y)   ASSUME_YES=1; shift ;;
        -h|--help)  usage 0 ;;
        *)          warn "unbekannte Option: $1"; usage 1 ;;
    esac
done

[[ $EUID -eq 0 ]] || die "bitte mit sudo bzw. als root ausführen"
[[ -f "$SRC/pyproject.toml" && -d "$SRC/haproxy_ui" ]] || die "install.sh muss im Projektverzeichnis liegen"
[[ -f /etc/debian_version ]] || warn "kein Debian erkannt – fahre trotzdem fort"

UPDATE=0
[[ -x "$VENV/bin/haproxy-ui" ]] && UPDATE=1
FIRST_CONF=0
[[ -f "$CONF" ]] || FIRST_CONF=1

ask() {  # ask VAR "Frage" "Vorgabe"
    local __var=$1 __q=$2 __def=$3 __ans
    if ((ASSUME_YES)) || [[ ! -t 0 ]]; then printf -v "$__var" '%s' "$__def"; return; fi
    read -r -p "$__q [$__def]: " __ans
    printf -v "$__var" '%s' "${__ans:-$__def}"
}

# Bei der Erstinstallation fehlende Angaben erfragen
if ((FIRST_CONF)); then
    [[ -n $LISTEN ]] || ask LISTEN "Adresse der Oberfläche (127.0.0.1 = nur lokal, 0.0.0.0 = alle)" 127.0.0.1
    [[ -n $PORT ]] || ask PORT "Port der Oberfläche" 8765
    if [[ -z $TLS_MODE ]]; then
        def=none; [[ $LISTEN != 127.0.0.1 && $LISTEN != ::1 ]] && def=self-signed
        ask TLS_MODE "HTTPS? (self-signed / none)" "$def"
    fi
fi

# Angaben prüfen
if [[ -n $LISTEN ]]; then
    python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$LISTEN" 2>/dev/null \
        || die "--listen: keine gültige IP-Adresse: $LISTEN"
    if [[ $LISTEN != 0.0.0.0 && $LISTEN != :: ]] && ! ip -o addr show | grep -qw -- "${LISTEN}"; then
        warn "die Adresse $LISTEN ist auf diesem Server nicht konfiguriert"
    fi
fi
if [[ -n $PORT ]]; then
    [[ $PORT =~ ^[0-9]{1,5}$ ]] && ((PORT >= 1 && PORT <= 65535)) || die "--port: Zahl von 1 bis 65535 erwartet"
    ((PORT == 80 || PORT == 443)) && warn "Port $PORT wird normalerweise von HAProxy selbst belegt"
    if ss -ltnH "sport = :$PORT" 2>/dev/null | grep -q . && ! systemctl is-active --quiet haproxy-ui; then
        warn "Port $PORT ist bereits belegt"
    fi
fi
case "$TLS_MODE" in
    ""|none|self-signed) ;;
    custom)
        [[ -n $TLS_CERT && -n $TLS_KEY ]] || die "--tls-cert und --tls-key nur gemeinsam angeben"
        [[ -f $TLS_CERT && -f $TLS_KEY ]] || die "Zertifikat oder Schlüssel nicht gefunden"
        TLS_CERT=$(readlink -f "$TLS_CERT"); TLS_KEY=$(readlink -f "$TLS_KEY") ;;
    *) die "--tls: self-signed oder none erwartet (oder --tls-cert/--tls-key)" ;;
esac

# --- Pakete --------------------------------------------------------------------
info "Systempakete prüfen"
need=()
command -v python3 >/dev/null || need+=(python3)
python3 -c 'import venv, ensurepip' 2>/dev/null || need+=(python3-venv)
command -v sudo >/dev/null || need+=(sudo)
[[ $TLS_MODE == self-signed ]] && ! command -v openssl >/dev/null && need+=(openssl)
if ((${#need[@]})); then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}"
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || die "Python 3.11 oder neuer nötig"
command -v haproxy >/dev/null || [[ -x /usr/sbin/haproxy ]] || warn "HAProxy ist nicht installiert (apt install haproxy)"

# --- Benutzer und Verzeichnisse --------------------------------------------------
if ! id "$APP_USER" >/dev/null 2>&1; then
    info "Systembenutzer $APP_USER anlegen"
    useradd --system --user-group --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$APP_USER"
fi
install -d -m 0755 -o root -g root "$PREFIX"
install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR"
install -d -m 0750 -o root -g "$APP_USER" "$CONF_DIR"

# --- Dienst anhalten und Datenbank sichern (nur beim Update) ----------------------
if ((UPDATE)); then
    info "Update: Dienst anhalten"
    systemctl stop haproxy-ui 2>/dev/null || true
    if [[ -f "$DATA_DIR/haproxy-ui.db" ]]; then
        stamp=$(date +%Y%m%d-%H%M%S)
        install -d -m 0700 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR/db-backup"
        cp -a "$DATA_DIR/haproxy-ui.db" "$DATA_DIR/db-backup/haproxy-ui-$stamp.db"
        info "Datenbank gesichert: $DATA_DIR/db-backup/haproxy-ui-$stamp.db"
        # nur die letzten 10 Sicherungen behalten
        ls -1t "$DATA_DIR"/db-backup/haproxy-ui-*.db 2>/dev/null | tail -n +11 | xargs -r rm -f
    fi
fi

# --- Programmdateien ----------------------------------------------------------------
info "Programmdateien nach $APP_DIR kopieren"
NEW_DIR=$(mktemp -d "$PREFIX/.app-new.XXXXXX")
tar -C "$SRC" --exclude=.git --exclude=.venv --exclude='__pycache__' --exclude='*.egg-info' \
    --exclude=.pytest_cache --exclude=build --exclude=dev-data -cf - . | tar -C "$NEW_DIR" -xf -
chown -R root:root "$NEW_DIR"
chmod 0755 "$NEW_DIR"
rm -rf "$APP_DIR.old"
[[ -d "$APP_DIR" ]] && mv "$APP_DIR" "$APP_DIR.old"
mv "$NEW_DIR" "$APP_DIR"
rm -rf "$APP_DIR.old"

info "Python-Umgebung in $VENV einrichten"
[[ -x "$VENV/bin/python" ]] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --disable-pip-version-check -r "$APP_DIR/requirements.txt"
"$VENV/bin/pip" install -q --disable-pip-version-check --no-deps --force-reinstall "$APP_DIR"

# --- Konfiguration --------------------------------------------------------------------
# set_conf KEY TOML-WERT: Zeile ersetzen (auch auskommentierte) oder anhängen
set_conf() {
    local key=$1 value=$2
    if grep -Eq "^#? *$key *=" "$CONF"; then
        sed -i -E "s|^#? *$key *=.*|$key = $value|" "$CONF"
    else
        printf '%s = %s\n' "$key" "$value" >> "$CONF"
    fi
}
unset_conf() { sed -i -E "s|^($1 *=.*)|# \1|" "$CONF"; }

if ((FIRST_CONF)); then
    info "Konfiguration $CONF anlegen"
    install -m 0640 -o root -g "$APP_USER" "$APP_DIR/deploy/config.example.toml" "$CONF"
else
    info "Konfiguration $CONF beibehalten (nur ausdrücklich angegebene Optionen werden geändert)"
fi
[[ -n $LISTEN ]] && set_conf listen_host "\"$LISTEN\""
[[ -n $PORT ]] && set_conf listen_port "$PORT"

case "$TLS_MODE" in
    self-signed)
        install -d -m 0750 -o root -g "$APP_USER" "$TLS_DIR"
        if [[ -f $TLS_DIR/cert.pem && -f $TLS_DIR/key.pem ]]; then
            info "vorhandenes Zertifikat in $TLS_DIR wird weiter benutzt"
        else
            info "selbst signiertes Zertifikat erzeugen"
            san="DNS:$(hostname -f 2>/dev/null || hostname),DNS:localhost,IP:127.0.0.1"
            for ip in $(hostname -I 2>/dev/null); do san+=",IP:$ip"; done
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
                -subj "/CN=$(hostname -f 2>/dev/null || hostname)" -addext "subjectAltName=$san" \
                -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" 2>/dev/null
            chown root:"$APP_USER" "$TLS_DIR/key.pem" "$TLS_DIR/cert.pem"
            chmod 0640 "$TLS_DIR/key.pem"; chmod 0644 "$TLS_DIR/cert.pem"
        fi
        set_conf tls_cert "\"$TLS_DIR/cert.pem\""
        set_conf tls_key "\"$TLS_DIR/key.pem\""
        info "SHA-256-Fingerabdruck (beim ersten Aufruf im Browser vergleichen):"
        openssl x509 -in "$TLS_DIR/cert.pem" -noout -fingerprint -sha256 | sed 's/^/    /'
        ;;
    custom)
        sudo -u "$APP_USER" test -r "$TLS_CERT" && sudo -u "$APP_USER" test -r "$TLS_KEY" \
            || warn "Benutzer $APP_USER kann Zertifikat oder Schlüssel nicht lesen – Rechte anpassen (z. B. Gruppe $APP_USER)"
        set_conf tls_cert "\"$TLS_CERT\""
        set_conf tls_key "\"$TLS_KEY\""
        ;;
    none)
        unset_conf tls_cert
        unset_conf tls_key
        ;;
esac

# Warnung bei unverschlüsseltem Zugang von außen
cur_host=$(sed -nE 's/^listen_host *= *"([^"]*)".*/\1/p' "$CONF" | tail -1)
cur_port=$(sed -nE 's/^listen_port *= *([0-9]+).*/\1/p' "$CONF" | tail -1)
cur_host=${cur_host:-127.0.0.1}; cur_port=${cur_port:-8765}
scheme=http; grep -Eq '^tls_cert *=' "$CONF" && scheme=https
if [[ $cur_host != 127.0.0.1 && $cur_host != ::1 && $scheme == http ]]; then
    warn "die Oberfläche ist auf $cur_host OHNE HTTPS erreichbar – Passwort und Sitzung gehen im Klartext übers Netz. Empfehlung: --tls self-signed"
fi

# --- Rechte auf /etc/haproxy (Schreibrecht über die Gruppe) ----------------------------
if [[ -d "$HAPROXY_DIR" ]]; then
    info "Schreibrecht für Gruppe $APP_USER auf $HAPROXY_DIR"
    chgrp "$APP_USER" "$HAPROXY_DIR"
    chmod g+rwx,g+s "$HAPROXY_DIR"
    install -d -m 2770 -o root -g "$APP_USER" "$HAPROXY_DIR/backup"
else
    warn "$HAPROXY_DIR fehlt – nach der HAProxy-Installation install.sh erneut ausführen"
fi

# --- sudoers ------------------------------------------------------------------------------
info "sudoers-Regel installieren (nur: systemctl reload haproxy)"
tmp_sudo=$(mktemp)
cp "$APP_DIR/deploy/sudoers.haproxy-ui" "$tmp_sudo"
visudo -cf "$tmp_sudo" >/dev/null || { rm -f "$tmp_sudo"; die "sudoers-Datei ungültig"; }
install -m 0440 -o root -g root "$tmp_sudo" "$SUDOERS"
rm -f "$tmp_sudo"

# --- systemd -------------------------------------------------------------------------------
info "systemd-Unit installieren"
install -m 0644 "$APP_DIR/deploy/haproxy-ui.service" "$UNIT"
systemctl daemon-reload
systemctl enable --quiet haproxy-ui
systemctl restart haproxy-ui
sleep 1
if systemctl is-active --quiet haproxy-ui; then
    info "haproxy-ui läuft auf $scheme://$cur_host:$cur_port/"
else
    warn "haproxy-ui ist nicht gestartet – siehe: journalctl -u haproxy-ui -n 50"
fi

RUN_AS=(sudo -u "$APP_USER" HAPROXY_UI_CONFIG="$CONF" "$VENV/bin/haproxy-ui")
if ((UPDATE)); then
    info "Update abgeschlossen."
else
    url_host=$cur_host; [[ $url_host == 0.0.0.0 ]] && url_host="<server-ip>"
    cat <<EOF

Installation abgeschlossen. Nächste Schritte:

  1. Bestehende haproxy.cfg einmalig importieren:
       ${RUN_AS[*]} import-cfg
  2. Admin-Konto anlegen:
       ${RUN_AS[*]} create-admin
  3. Im Browser öffnen: $scheme://$url_host:$cur_port/
EOF
    if [[ $cur_host == 127.0.0.1 || $cur_host == ::1 ]]; then
        echo "     (von außen per SSH-Tunnel: ssh -L $cur_port:127.0.0.1:$cur_port root@<dieser-host>)"
    fi
    echo
fi
