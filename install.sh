#!/usr/bin/env bash
# JAWAKER Panel — one-line VPS installer
#
#   curl -sSL https://raw.githubusercontent.com/bukansembarangkong/jawaker-panel/main/install.sh | bash
#
# Requirements: Debian/Ubuntu/RHEL/Rocky/AlmaLinux VPS, run as root.
# Installs: PostgreSQL, Go toolchain (if absent), JAWAKER binary, systemd unit.
set -euo pipefail

###############################################################################
# Config
###############################################################################
REPO="https://github.com/bukansembarangkong/jawaker-panel.git"
INSTALL_DIR="/opt/jawaker-panel"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/jawaker"
SERVICE="jawaker-controller"
LISTEN_PORT="${JAWAKER_PORT:-8080}"
DB_NAME="jawaker_panel"
DB_USER="jawaker"

###############################################################################
# Helpers
###############################################################################
bold() { printf "\033[1m%s\033[0m\n" "$*"; }
info() { printf "\033[0;34m[jawaker] %s\033[0m\n" "$*"; }
ok()   { printf "\033[0;32m[jawaker] ✓ %s\033[0m\n" "$*"; }
warn() { printf "\033[0;33m[jawaker] ⚠ %s\033[0m\n" "$*"; }
err()  { printf "\033[0;31m[jawaker] ✗ %s\033[0m\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

gen_secret() { head -c 32 /dev/urandom | base64 | tr -d '\n/+=' | head -c 43; }
gen_pass()   { head -c 24 /dev/urandom | base64 | tr -d '\n/+=' | head -c 32; }
server_ip()  { hostname -I 2>/dev/null | awk '{print $1}'; }

###############################################################################
# Preflight checks
###############################################################################
[ "$(id -u)" -eq 0 ] || die "Run as root (e.g. sudo bash install.sh)"

# Detect OS and package manager
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt"
    PG_PKG="postgresql postgresql-client"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    PG_PKG="postgresql-server postgresql"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    PG_PKG="postgresql-server postgresql"
else
    die "Unsupported OS: need apt-get, dnf, or yum"
fi

###############################################################################
# Banner
###############################################################################
echo ""
bold "╔══════════════════════════════════════════╗"
bold "║        JAWAKER Panel Installer           ║"
bold "╚══════════════════════════════════════════╝"
echo ""

###############################################################################
# System dependencies
###############################################################################
info "Installing system dependencies..."
case "$PKG_MANAGER" in
    apt)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq $PG_PKG curl git tar build-essential
        ;;
    dnf)
        dnf install -y -q $PG_PKG curl git tar gcc
        if ! systemctl is-enabled postgresql &>/dev/null; then
            postgresql-setup --initdb 2>/dev/null || true
        fi
        ;;
    yum)
        yum install -y -q $PG_PKG curl git tar gcc
        if ! systemctl is-enabled postgresql &>/dev/null; then
            service postgresql initdb 2>/dev/null || true
        fi
        ;;
esac
ok "System packages ready"

###############################################################################
# Go toolchain
###############################################################################
if ! command -v go &>/dev/null; then
    info "Installing Go 1.23..."
    GO_VER="1.23.4"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GO_ARCH="amd64" ;;
        aarch64) GO_ARCH="arm64" ;;
        *)        die "Unsupported CPU arch: $ARCH" ;;
    esac
    GO_TAR="go${GO_VER}.linux-${GO_ARCH}.tar.gz"
    curl -sSL "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}"
    tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm -f "/tmp/${GO_TAR}"
    export PATH="/usr/local/go/bin:$PATH"
    ok "Go $(go version | awk '{print $3}') installed"
else
    ok "Go $(go version | awk '{print $3}') already present"
fi
export PATH="/usr/local/go/bin:$PATH"

###############################################################################
# Node/npm (for frontend build)
###############################################################################
if ! command -v node &>/dev/null; then
    info "Installing Node.js 20..."
    case "$PKG_MANAGER" in
        apt)
            curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
            apt-get install -y -qq nodejs
            ;;
        dnf|yum)
            curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
            $PKG_MANAGER install -y -q nodejs npm
            ;;
    esac
    ok "Node.js $(node --version) installed"
else
    ok "Node.js $(node --version) already present"
fi

###############################################################################
# PostgreSQL setup
###############################################################################
info "Starting PostgreSQL..."
case "$PKG_MANAGER" in
    apt)  systemctl enable --now postgresql ;;
    dnf)  systemctl enable --now postgresql ;;
    yum)  systemctl enable --now postgresql ;;
esac

DB_PASS=$(gen_pass)

info "Creating database user and database..."
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" 2>/dev/null | grep -q 1; then
    info "User '${DB_USER}' already exists — resetting password"
    sudo -u postgres psql -c "ALTER ROLE ${DB_USER} WITH PASSWORD '${DB_PASS}';" >/dev/null
else
    sudo -u postgres psql -c "CREATE ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASS}';" >/dev/null
fi

if sudo -u postgres psql -lqt 2>/dev/null | cut -d'|' -f1 | grep -qw "${DB_NAME}"; then
    ok "Database '${DB_NAME}' already exists"
else
    sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" >/dev/null
    ok "Database '${DB_NAME}' created"
fi
ok "PostgreSQL configured"

###############################################################################
# Fetch and build JAWAKER
###############################################################################
info "Cloning JAWAKER Panel..."
if [ -d "${INSTALL_DIR}/.git" ]; then
    git -C "${INSTALL_DIR}" pull --quiet
else
    git clone --quiet --depth=1 "${REPO}" "${INSTALL_DIR}"
fi
ok "Source code ready"

info "Building frontend..."
cd "${INSTALL_DIR}/apps/web"
npm ci --silent
npm run build --silent
ok "Frontend built"

info "Copying frontend build into embed directory..."
rm -rf "${INSTALL_DIR}/cmd/controller/webdist/dist"
cp -r "${INSTALL_DIR}/apps/web/dist" "${INSTALL_DIR}/cmd/controller/webdist/dist"
ok "Frontend embedded"

info "Compiling jawaker-controller..."
cd "${INSTALL_DIR}"
go build -ldflags="-s -w" -o "${BIN_DIR}/jawaker-controller" ./cmd/controller
ok "Binary installed at ${BIN_DIR}/jawaker-controller"

###############################################################################
# Configuration
###############################################################################
SECRET_KEY=$(gen_secret)
ADMIN_PASS=$(gen_pass)
DATABASE_URL="postgres://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}?sslmode=disable"

mkdir -p "${CONF_DIR}"
chmod 700 "${CONF_DIR}"

cat >"${CONF_DIR}/jawaker.env" <<EOF
# JAWAKER Panel configuration — generated by install.sh
# Edit and restart: systemctl restart jawaker-controller

JAWAKER_DATABASE_URL=${DATABASE_URL}
JAWAKER_SECRET_KEY_V1=${SECRET_KEY}
JAWAKER_LISTEN_ADDR=:${LISTEN_PORT}
JAWAKER_RUN_MIGRATIONS=true
JAWAKER_COOKIE_SECURE=false
JAWAKER_COOKIE_ALLOW_INSECURE=true
JAWAKER_LOG_LEVEL=info
JAWAKER_LOG_FORMAT=json
JAWAKER_BOOTSTRAP_ADMIN_EMAIL=admin@jawaker.local
JAWAKER_BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PASS}
EOF
chmod 600 "${CONF_DIR}/jawaker.env"
ok "Configuration written to ${CONF_DIR}/jawaker.env"

###############################################################################
# Systemd service
###############################################################################
cat >/etc/systemd/system/${SERVICE}.service <<EOF
[Unit]
Description=JAWAKER Control Plane
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=root
EnvironmentFile=${CONF_DIR}/jawaker.env
ExecStart=${BIN_DIR}/jawaker-controller
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=jawaker-controller

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${SERVICE}
ok "Service started: ${SERVICE}"

###############################################################################
# Run migrations
###############################################################################
info "Waiting for service to run migrations..."
sleep 5
if systemctl is-active --quiet ${SERVICE}; then
    ok "Service is running"
else
    warn "Service may not be running — check: journalctl -u ${SERVICE} -n 50"
fi

###############################################################################
# Done — print access info
###############################################################################
IP=$(server_ip)
echo ""
bold "╔══════════════════════════════════════════════════════╗"
bold "║              JAWAKER Panel is ready! 🎉              ║"
bold "╠══════════════════════════════════════════════════════╣"
bold "║                                                      ║"
printf  "║  URL:      \033[1mhttp://%-36s\033[0m║\n" "${IP}:${LISTEN_PORT}/"
printf  "║  Email:    %-42s║\n" "admin@jawaker.local"
printf  "║  Password: \033[1m%-42s\033[0m║\n" "${ADMIN_PASS}"
bold "║                                                      ║"
bold "║  Config:   /etc/jawaker/jawaker.env                  ║"
bold "║  Logs:     journalctl -u jawaker-controller -f       ║"
bold "║                                                      ║"
bold "╚══════════════════════════════════════════════════════╝"
echo ""
warn "Save your admin password now — it will not be shown again!"
echo ""
