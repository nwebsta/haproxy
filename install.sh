#!/usr/bin/env bash
# haproxy-ui: Installation und Update auf Debian.
#
#   Erstinstallation:  git clone <repo> haproxy-ui && cd haproxy-ui && sudo ./install.sh
#   Update:            cd haproxy-ui && git pull && sudo ./install.sh
#
# Das Skript ist wiederholbar. Es überschreibt nie config.toml oder die Datenbank;
# vor jedem Update wird die Datenbank gesichert.
set -euo pipefail

APP_USER=haproxy-ui
PREFIX=/opt/haproxy-ui
APP_DIR=$PREFIX/app
VENV=$PREFIX/venv
DATA_DIR=/var/lib/haproxy-ui
CONF_DIR=/etc/haproxy-ui
HAPROXY_DIR=/etc/haproxy
UNIT=/etc/systemd/system/haproxy-ui.service
SUDOERS=/etc/sudoers.d/haproxy-ui
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mWarnung:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31mFehler:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "bitte mit sudo bzw. als root ausführen"
[[ -f "$SRC/pyproject.toml" && -d "$SRC/haproxy_ui" ]] || die "install.sh muss im Projektverzeichnis liegen"
[[ -f /etc/debian_version ]] || warn "kein Debian erkannt – fahre trotzdem fort"

UPDATE=0
[[ -x "$VENV/bin/haproxy-ui" ]] && UPDATE=1

# --- Pakete --------------------------------------------------------------------
info "Systempakete prüfen"
need=()
command -v python3 >/dev/null || need+=(python3)
python3 -c 'import venv, ensurepip' 2>/dev/null || need+=(python3-venv)
command -v sudo >/dev/null || need+=(sudo)
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
if [[ ! -f "$CONF_DIR/config.toml" ]]; then
    info "Konfiguration $CONF_DIR/config.toml anlegen"
    install -m 0640 -o root -g "$APP_USER" "$APP_DIR/deploy/config.example.toml" "$CONF_DIR/config.toml"
else
    info "Konfiguration $CONF_DIR/config.toml bleibt unverändert"
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
    info "haproxy-ui läuft"
else
    warn "haproxy-ui ist nicht gestartet – siehe: journalctl -u haproxy-ui -n 50"
fi

RUN_AS=(sudo -u "$APP_USER" HAPROXY_UI_CONFIG="$CONF_DIR/config.toml" "$VENV/bin/haproxy-ui")
if ((UPDATE)); then
    info "Update abgeschlossen."
else
    cat <<EOF

Installation abgeschlossen. Nächste Schritte:

  1. Bestehende haproxy.cfg einmalig importieren:
       ${RUN_AS[*]} import-cfg
  2. Admin-Konto anlegen:
       ${RUN_AS[*]} create-admin
  3. Per SSH-Tunnel öffnen:
       ssh -L 8765:127.0.0.1:8765 root@<dieser-host>
       http://127.0.0.1:8765/

EOF
fi
