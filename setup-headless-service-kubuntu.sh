#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE_NAME="e2nb2"
RUN_USER="e2nb2"
RUN_GROUP="e2nb2"
INSTALL_DIR="/opt/e2nb2"
CONFIG_DIR="/etc/e2nb2"
LOG_DIR="/var/log/e2nb2"
STATE_FILE="${INSTALL_DIR}/e2nb_state.json"
VENV_DIR="${INSTALL_DIR}/.venv"
PYTHON_BIN="python3"
NON_INTERACTIVE=0
AUTO_YES=0

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

print_usage() {
  cat <<USAGE
Usage: $0 [options]

Set up E2NB headless mode as a systemd service on Kubuntu/Ubuntu.

Options:
  --service-name NAME      systemd service name (default: e2nb)
  --run-user USER          service user account (default: e2nb)
  --install-dir PATH       application install directory (default: /opt/e2nb)
  --config-dir PATH        configuration directory (default: /etc/e2nb)
  --log-dir PATH           log directory (default: /var/log/e2nb)
  --python-bin PATH        python executable to use (default: python3)
  --non-interactive        fail instead of prompting for confirmations
  -y, --yes                auto-accept prompts
  -h, --help               show this help message
USAGE
}

log() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }
err() { echo "[ERROR] $*" >&2; }

confirm() {
  local msg="$1"
  if [[ "$AUTO_YES" -eq 1 ]]; then
    return 0
  fi
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
    err "$msg (use --yes to auto-confirm in non-interactive mode)."
    exit 1
  fi
  read -r -p "$msg [y/N]: " reply
  [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service-name) SERVICE_NAME="$2"; shift 2 ;;
    --run-user) RUN_USER="$2"; RUN_GROUP="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --config-dir) CONFIG_DIR="$2"; shift 2 ;;
    --log-dir) LOG_DIR="$2"; shift 2 ;;
    --python-bin) PYTHON_BIN="$2"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    -y|--yes) AUTO_YES=1; shift ;;
    -h|--help) print_usage; exit 0 ;;
    *) err "Unknown option: $1"; print_usage; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  log "Root privileges are required. Re-running with sudo..."
  exec sudo bash "$0" "$@"
fi

if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  if [[ "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *"ubuntu"* ]]; then
    warn "This installer is tuned for Kubuntu/Ubuntu. Detected: ${PRETTY_NAME:-unknown}."
    confirm "Continue anyway?" || exit 1
  fi
fi

for required in e2nb_core.py e2nb-headless.py requirements.txt config.ini; do
  if [[ ! -f "${SCRIPT_DIR}/${required}" ]]; then
    err "Missing required file in script directory: ${required}"
    err "Run this script from the cloned e2nb repository."
    exit 1
  fi
done

SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
STATE_FILE="${INSTALL_DIR}/e2nb_state.json"

log "Installing system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  python3 python3-venv python3-pip ca-certificates

if ! id -u "$RUN_USER" >/dev/null 2>&1; then
  log "Creating system user: ${RUN_USER}"
  useradd -r -s /usr/sbin/nologin -m "$RUN_USER"
else
  log "User ${RUN_USER} already exists."
fi

log "Creating directories..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"

log "Copying application files..."
install -m 0644 "${SCRIPT_DIR}/e2nb_core.py" "${INSTALL_DIR}/e2nb_core.py"
install -m 0644 "${SCRIPT_DIR}/e2nb-headless.py" "${INSTALL_DIR}/e2nb-headless.py"
install -m 0644 "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/requirements.txt"

if [[ -f "${CONFIG_DIR}/config.ini" ]]; then
  warn "Existing config found: ${CONFIG_DIR}/config.ini"
  if confirm "Back up and replace config.ini with repository template?"; then
    cp -a "${CONFIG_DIR}/config.ini" "${CONFIG_DIR}/config.ini.bak.$(date +%Y%m%d%H%M%S)"
    install -m 0640 "${SCRIPT_DIR}/config.ini" "${CONFIG_DIR}/config.ini"
  else
    log "Keeping existing config.ini"
  fi
else
  install -m 0640 "${SCRIPT_DIR}/config.ini" "${CONFIG_DIR}/config.ini"
  log "Installed starter config at ${CONFIG_DIR}/config.ini"
fi

if [[ ! -d "$VENV_DIR" ]]; then
  log "Creating Python virtual environment..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

log "Upgrading pip and installing dependencies..."
"${VENV_DIR}/bin/pip" install --upgrade pip
"${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"

log "Creating log file..."
touch "${LOG_DIR}/${SERVICE_NAME}.log"

cat > "$SERVICE_PATH" <<SERVICE
[Unit]
Description=E2NB Email to Notification Blaster (${SERVICE_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_GROUP}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${VENV_DIR}/bin/python ${INSTALL_DIR}/e2nb-headless.py -c ${CONFIG_DIR}/config.ini -l ${LOG_DIR}/${SERVICE_NAME}.log --no-console
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${INSTALL_DIR} ${LOG_DIR} ${CONFIG_DIR}
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
SERVICE

log "Setting ownership..."
chown -R "${RUN_USER}:${RUN_GROUP}" "$INSTALL_DIR" "$LOG_DIR"
chown root:"${RUN_GROUP}" "${CONFIG_DIR}/config.ini"
chmod 0640 "${CONFIG_DIR}/config.ini"

log "Reloading systemd and starting service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

sleep 1
if systemctl is-active --quiet "$SERVICE_NAME"; then
  log "Service ${SERVICE_NAME} is running."
else
  warn "Service ${SERVICE_NAME} is not active yet. Showing status for troubleshooting:"
  systemctl status "$SERVICE_NAME" --no-pager || true
fi

cat <<NEXT

Setup complete.

Useful commands:
  sudo systemctl status ${SERVICE_NAME}
  sudo journalctl -u ${SERVICE_NAME} -f
  sudo systemctl reload ${SERVICE_NAME}     # reload config.ini without restart

Config file:
  ${CONFIG_DIR}/config.ini

Log file:
  ${LOG_DIR}/${SERVICE_NAME}.log

NOTE: Edit config.ini with your real source/channel credentials before production use.
NEXT
