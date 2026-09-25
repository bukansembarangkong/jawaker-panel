#!/usr/bin/env bash
# JAWAKER Panel — one-line VPS installer
#
#   curl -sSL https://raw.githubusercontent.com/bukansembarangkong/jawaker-panel/main/install.sh | bash
#
# Environment overrides (optional):
#   JAWAKER_DOMAIN       - panel domain, e.g. "panel.example.com"  (skips interactive prompt)
#   JAWAKER_SSL_EMAIL    - email for Let's Encrypt (required when JAWAKER_DOMAIN is set)
#   JAWAKER_PORT         - panel port when no domain/SSL (default: 8443)
#   JAWAKER_ADMIN_EMAIL  - initial admin account email (default: admin@jawaker.local)
#
# Requirements: Debian/Ubuntu/RHEL/Rocky/AlmaLinux, run as root.
set -euo pipefail

###############################################################################
# Config
###############################################################################
REPO="https://github.com/bukansembarangkong/jawaker-panel.git"
INSTALL_DIR="/opt/jawaker-panel"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/jawaker"
SERVICE="jawaker-controller"
# Default panel port (used when no domain/SSL is configured).
# Override with JAWAKER_PORT env var or the interactive prompt.
CONTROLLER_PORT="8443"
PANEL_PORT="${JAWAKER_PORT:-}"   # resolved to CONTROLLER_PORT after prompts
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
# Preflight
###############################################################################
[ "$(id -u)" -eq 0 ] || die "Run as root (e.g. sudo bash install.sh)"

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
# Domain + SSL prompt
###############################################################################
DOMAIN="${JAWAKER_DOMAIN:-}"
SSL_EMAIL="${JAWAKER_SSL_EMAIL:-}"
USE_SSL=false

# Check if an interactive terminal is attached (even when piped via curl ... | bash)
has_tty() { [ -c /dev/tty ]; }

# Only prompt when a real terminal is attached and domain is not pre-set via env
if has_tty && [ -z "$DOMAIN" ]; then
    echo ""
    info "Optional: bind a domain for HTTPS access (e.g. panel.example.com)"
    info "  • Leave empty to access via IP on a custom port"
    info "  • DNS A record for the domain must already point to this server"
    echo ""
    read -rp "Panel domain [leave empty for IP-only]: " DOMAIN < /dev/tty
    DOMAIN="${DOMAIN// /}"  # trim spaces
fi

if [ -n "$DOMAIN" ]; then
    USE_SSL=true
    if [ -z "$SSL_EMAIL" ] && has_tty; then
        read -rp "Email for Let's Encrypt SSL certificate: " SSL_EMAIL < /dev/tty
    fi
    [ -n "$SSL_EMAIL" ] || die "JAWAKER_SSL_EMAIL is required when a domain is provided"
    info "Will configure HTTPS for: ${DOMAIN}"
fi

# ── Interactive port selector (arrow keys / vim keys / Enter) ─────────────────
# menu_select <selected_var> <item1> [item2 ...] — sets selected_var to the
# index (0-based) of the chosen item. Reads directly from /dev/tty.
menu_select() {
    local _var="$1"; shift
    local _items=("$@")
    local _n=${#_items[@]}
    local _cur=0

    # Hide cursor, save position
    tput civis 2>/dev/null || true

    _draw_menu() {
        # Move cursor up _n lines if not first draw
        [ "${_first_draw:-1}" -eq 0 ] && tput cuu "$_n" 2>/dev/null
        _first_draw=0
        for i in $(seq 0 $((_n - 1))); do
            if [ "$i" -eq "$_cur" ]; then
                printf "\r  \033[1;32m❯ %-40s\033[0m\n" "${_items[$i]}"
            else
                printf "\r    \033[0m%-40s\033[0m\n" "${_items[$i]}"
            fi
        done
    }

    _first_draw=1
    _draw_menu

    while true; do
        # Read from /dev/tty directly (handles curl ... | bash piping)
        IFS= read -rsn1 _k < /dev/tty
        if [ "$_k" = $'\x1b' ]; then
            IFS= read -rsn1 -t 0.1 _k2 < /dev/tty
            IFS= read -rsn1 -t 0.1 _k3 < /dev/tty
            if [ "$_k2" = '[' ]; then
                case "$_k3" in
                    A)  # Up arrow
                        [ "$_cur" -gt 0 ] && _cur=$((_cur - 1))
                        ;;
                    B)  # Down arrow
                        [ "$_cur" -lt $((_n - 1)) ] && _cur=$((_cur + 1))
                        ;;
                esac
            fi
        elif [ "$_k" = 'k' ] || [ "$_k" = 'K' ]; then  # vim up
            [ "$_cur" -gt 0 ] && _cur=$((_cur - 1))
        elif [ "$_k" = 'j' ] || [ "$_k" = 'J' ]; then  # vim down
            [ "$_cur" -lt $((_n - 1)) ] && _cur=$((_cur + 1))
        elif [ -z "$_k" ]; then  # Enter
            break
        fi
        _draw_menu
    done

    tput cnorm 2>/dev/null || true  # Restore cursor
    printf '\n'
    eval "$_var=$_cur"
}

# Port selection — only relevant when no domain (direct port access).
# With a domain, Nginx handles standard 80/443.
if ! $USE_SSL && [ -z "$PANEL_PORT" ]; then

    # Port labels: describe CLOUD DEFAULT reachability, not just local bind status.
    # Port 80/443 are open by default on almost all VPS providers.
    # Higher ports usually need a manual cloud firewall/security-group rule.
    declare -A _PORT_DESC
    _PORT_DESC[80]="Port 80   — Standard HTTP, open by default on all clouds ✓"
    _PORT_DESC[443]="Port 443  — Standard HTTPS (needs SSL cert), open by default ✓"
    _PORT_DESC[8080]="Port 8080 — Alternative HTTP, may need cloud firewall rule"
    _PORT_DESC[8443]="Port 8443 — Alternative HTTPS, may need cloud firewall rule"
    _PORT_DESC[3000]="Port 3000 — Development port, may need cloud firewall rule"

    _CANDIDATES="80 443 8080 8443 3000"
    _MENU_ITEMS=()
    _MENU_PORTS=()

    for _p in $_CANDIDATES; do
        # Skip port 443 without domain (no SSL cert)
        [ "$_p" -eq 443 ] && continue
        if ss -tlnp 2>/dev/null | grep -q ":${_p} "; then
            _MENU_ITEMS+=("${_PORT_DESC[$_p]}  [already in use by another process]")
        else
            _MENU_ITEMS+=("${_PORT_DESC[$_p]}")
            _MENU_PORTS+=("$_p")
        fi
    done
    _MENU_ITEMS+=("Custom port...")

    if has_tty; then
        echo ""
        printf "\033[1m  Select panel port\033[0m\n"
        printf "  \033[0;33mNote: ports 80 is open by default on most cloud VPS.\033[0m\n"
        printf "  \033[0;33mOther ports may require a firewall rule in your cloud dashboard.\033[0m\n"
        printf "  (↑↓ or j/k to move, Enter to select)\n\n"
        menu_select _SEL_IDX "${_MENU_ITEMS[@]}"

        if [ "${_MENU_ITEMS[$_SEL_IDX]}" = "Custom port..." ]; then
            while true; do
                read -rp "  Enter custom port number: " _port_input < /dev/tty
                _port_input="${_port_input// /}"
                if echo "$_port_input" | grep -qE '^[0-9]+$' && \
                   [ "$_port_input" -ge 1 ] && [ "$_port_input" -le 65535 ]; then
                    PANEL_PORT="$_port_input"
                    break
                fi
                warn "Invalid port. Must be a number between 1 and 65535."
            done
        else
            PANEL_PORT=$(echo "${_MENU_ITEMS[$_SEL_IDX]}" | grep -oE 'Port ([0-9]+)' | grep -oE '[0-9]+' | head -1)
            if [ -z "$PANEL_PORT" ]; then
                PANEL_PORT="${_MENU_PORTS[0]:-80}"
                warn "Could not parse port. Defaulting to ${PANEL_PORT}."
            fi
        fi

        # ── Test real external reachability ────────────────────────────────
        _SERVER_IP=$(server_ip)
        USE_CLOUDFLARE=false

        _probe_port() {
            local _p="$1"
            _PROBE_PID=""
            if command -v python3 &>/dev/null; then
                python3 -c "import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('', ${_p})); s.listen(1); time.sleep(8)" &>/dev/null &
                _PROBE_PID=$!
            elif command -v nc &>/dev/null; then
                nc -l -p "${_p}" &>/dev/null &
                _PROBE_PID=$!
            fi
            if [ -z "$_PROBE_PID" ]; then echo "skip"; return; fi
            sleep 1
            local _r
            _r=$(curl -s --max-time 6 \
                "https://portchecker.io/api/v2/query" \
                -H "Content-Type: application/json" \
                -d "{\"host\":\"${_SERVER_IP}\",\"ports\":[\"${_p}\"]}" 2>/dev/null \
                | grep -o '"isOpen":true' || true)
            kill $_PROBE_PID 2>/dev/null || true
            wait $_PROBE_PID 2>/dev/null || true
            echo "$_r"
        }

        if [ -n "$_SERVER_IP" ] && command -v curl &>/dev/null; then
            info "Testing if port ${PANEL_PORT} is reachable from the internet..."
            _REACH=$(_probe_port "$PANEL_PORT")

            if [ -n "$_REACH" ] && [ "$_REACH" != "skip" ]; then
                ok "Port ${PANEL_PORT} is confirmed reachable from the internet ✓"
            else
                # ── Port is blocked — show options ──────────────────────────
                while true; do
                    echo ""
                    printf "\033[1;33m  ✗ Port ${PANEL_PORT} is BLOCKED by your cloud firewall.\033[0m\n"
                    echo ""
                    echo "  What would you like to do?"
                    echo ""
                    _BLOCK_OPTS=(
                        "I've opened port ${PANEL_PORT} in my cloud dashboard — retry"
                        "Choose a different port"
                        "Use Cloudflare Tunnel (no port opening needed, free HTTPS URL)"
                    )
                    menu_select _BLOCK_SEL "${_BLOCK_OPTS[@]}"

                    case "$_BLOCK_SEL" in
                        0)  # Retry
                            info "Retrying port ${PANEL_PORT}..."
                            _REACH=$(_probe_port "$PANEL_PORT")
                            if [ -n "$_REACH" ] && [ "$_REACH" != "skip" ]; then
                                ok "Port ${PANEL_PORT} is now reachable ✓"
                                break
                            else
                                warn "Still blocked. Try opening the port or choose another option."
                            fi
                            ;;
                        1)  # Different port — re-show port menu
                            echo ""
                            printf "\033[1m  Select a different port\033[0m (↑↓ / j/k, Enter to select):\n\n"
                            menu_select _SEL_IDX "${_MENU_ITEMS[@]}"
                            if [ "${_MENU_ITEMS[$_SEL_IDX]}" = "Custom port..." ]; then
                                while true; do
                                    read -rp "  Enter custom port number: " _port_input < /dev/tty
                                    _port_input="${_port_input// /}"
                                    if echo "$_port_input" | grep -qE '^[0-9]+$' && \
                                       [ "$_port_input" -ge 1 ] && [ "$_port_input" -le 65535 ]; then
                                        PANEL_PORT="$_port_input"; break
                                    fi
                                    warn "Invalid port."
                                done
                            else
                                PANEL_PORT=$(echo "${_MENU_ITEMS[$_SEL_IDX]}" | grep -oE 'Port ([0-9]+)' | grep -oE '[0-9]+' | head -1)
                                PANEL_PORT="${PANEL_PORT:-80}"
                            fi
                            info "Testing port ${PANEL_PORT}..."
                            _REACH=$(_probe_port "$PANEL_PORT")
                            if [ -n "$_REACH" ] && [ "$_REACH" != "skip" ]; then
                                ok "Port ${PANEL_PORT} is reachable ✓"
                                break
                            else
                                warn "Port ${PANEL_PORT} is also blocked. Choose another option."
                            fi
                            ;;
                        2)  # Cloudflare Tunnel
                            USE_CLOUDFLARE=true
                            # Bind controller to loopback — Cloudflare proxies from outside
                            PANEL_PORT="8080"
                            ok "Cloudflare Tunnel selected — no port opening needed"
                            break
                            ;;
                    esac
                done
            fi
        fi
    else
        PANEL_PORT="${_MENU_PORTS[0]:-80}"
    fi
fi

# Resolve final panel port
PANEL_PORT="${PANEL_PORT:-80}"

# Auto-open port in local firewall if active (won't help cloud Security Groups,
# but handles ufw/firewalld on bare-metal and some providers).
if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    if $USE_SSL; then
        info "Opening ports 80/tcp and 443/tcp in ufw..."
        ufw allow 80/tcp >/dev/null
        ufw allow 443/tcp >/dev/null
        ok "ufw: ports 80, 443 allowed"
    else
        info "Opening port ${PANEL_PORT}/tcp in ufw..."
        ufw allow "${PANEL_PORT}/tcp" >/dev/null
        ok "ufw: port ${PANEL_PORT} allowed"
    fi
elif command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q "running"; then
    if $USE_SSL; then
        info "Opening ports 80/tcp and 443/tcp in firewalld..."
        firewall-cmd --permanent --add-port=80/tcp >/dev/null
        firewall-cmd --permanent --add-port=443/tcp >/dev/null
        firewall-cmd --reload >/dev/null
        ok "firewalld: ports 80, 443 allowed"
    else
        info "Opening port ${PANEL_PORT}/tcp in firewalld..."
        firewall-cmd --permanent --add-port="${PANEL_PORT}/tcp" >/dev/null
        firewall-cmd --reload >/dev/null
        ok "firewalld: port ${PANEL_PORT} allowed"
    fi
fi


###############################################################################
# System dependencies  [1/7]
###############################################################################
step() { printf "\033[1;36m\n[%s/7] %s\033[0m\n" "$1" "$2"; }
step 1 "Installing system packages"
case "$PKG_MANAGER" in
    apt)
        export DEBIAN_FRONTEND=noninteractive
        # Release stale locks if a previous install was interrupted
        if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
            warn "Stale package manager lock detected — clearing..."
            killall -9 apt-get apt dpkg 2>/dev/null || true
            sleep 1
            rm -f /var/lib/dpkg/lock* /var/lib/apt/lists/lock* /var/cache/apt/archives/lock* 2>/dev/null || true
            dpkg --configure -a 2>/dev/null || true
            ok "Lock cleared"
        fi
        apt-get update
        EXTRA_PKGS=""
        $USE_SSL && EXTRA_PKGS="nginx certbot python3-certbot-nginx"
        apt-get install -y $PG_PKG curl git tar build-essential $EXTRA_PKGS
        ;;
    dnf)
        dnf install -y $PG_PKG curl git tar gcc
        $USE_SSL && dnf install -y nginx certbot python3-certbot-nginx
        if ! systemctl is-enabled postgresql &>/dev/null; then
            postgresql-setup --initdb 2>/dev/null || true
        fi
        ;;
    yum)
        yum install -y $PG_PKG curl git tar gcc
        $USE_SSL && yum install -y nginx certbot python3-certbot-nginx
        if ! systemctl is-enabled postgresql &>/dev/null; then
            service postgresql initdb 2>/dev/null || true
        fi
        ;;
esac
ok "System packages installed"

###############################################################################
# Go toolchain  [2/7]
###############################################################################
step 2 "Setting up Go toolchain"
if ! command -v go &>/dev/null; then
    GO_VER="1.23.4"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GO_ARCH="amd64" ;;
        aarch64) GO_ARCH="arm64" ;;
        *)        die "Unsupported CPU arch: $ARCH" ;;
    esac
    GO_TAR="go${GO_VER}.linux-${GO_ARCH}.tar.gz"
    info "Downloading Go ${GO_VER} (${GO_ARCH})..."
    curl --progress-bar -L "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}"
    info "Extracting Go..."
    tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm -f "/tmp/${GO_TAR}"
    export PATH="/usr/local/go/bin:$PATH"
    ok "Go $(go version | awk '{print $3}') installed"
else
    ok "Go $(go version | awk '{print $3}') already present"
fi
export PATH="/usr/local/go/bin:$PATH"

###############################################################################
# Node/npm  [2/7 continued]
###############################################################################
if ! command -v node &>/dev/null; then
    info "Installing Node.js 20..."
    case "$PKG_MANAGER" in
        apt)
            curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
            apt-get install -y nodejs
            ;;
        dnf|yum)
            curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
            $PKG_MANAGER install -y nodejs npm
            ;;
    esac
    ok "Node.js $(node --version) installed"
else
    ok "Node.js $(node --version) already present"
fi

###############################################################################
# PostgreSQL setup  [3/7]
###############################################################################
step 3 "Configuring PostgreSQL"
info "Starting PostgreSQL service..."
systemctl enable --now postgresql
sleep 2

DB_PASS=$(gen_pass)

info "Creating database user '${DB_USER}'..."
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" 2>/dev/null | grep -q 1; then
    info "  User already exists — resetting password"
    sudo -u postgres psql -c "ALTER ROLE ${DB_USER} WITH PASSWORD '${DB_PASS}';" >/dev/null
else
    sudo -u postgres psql -c "CREATE ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASS}';" >/dev/null
    ok "  User '${DB_USER}' created"
fi

info "Creating database '${DB_NAME}'..."
if sudo -u postgres psql -lqt 2>/dev/null | cut -d'|' -f1 | grep -qw "${DB_NAME}"; then
    ok "  Database '${DB_NAME}' already exists"
else
    sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" >/dev/null
    ok "  Database '${DB_NAME}' created"
fi
ok "PostgreSQL configured"

###############################################################################
# Fetch JAWAKER source  [4/7]
###############################################################################
step 4 "Cloning JAWAKER Panel source"
if [ -d "${INSTALL_DIR}/.git" ]; then
    info "Updating existing installation..."
    git -C "${INSTALL_DIR}" pull
else
    git clone --depth=1 "${REPO}" "${INSTALL_DIR}"
fi
ok "Source code ready at ${INSTALL_DIR}"

###############################################################################
# Build JAWAKER  [5/7]
###############################################################################
step 5 "Building JAWAKER Panel"

info "Installing frontend dependencies (npm ci)..."
cd "${INSTALL_DIR}/apps/web"
npm ci

info "Building frontend assets..."
npm run build

info "Copying frontend into embed directory..."
rm -rf "${INSTALL_DIR}/cmd/controller/webdist/dist"
cp -r "${INSTALL_DIR}/apps/web/dist" "${INSTALL_DIR}/cmd/controller/webdist/dist"
ok "Frontend built and embedded"

info "Compiling jawaker-controller binary..."
cd "${INSTALL_DIR}"
go build -v -ldflags="-s -w" -o "${BIN_DIR}/jawaker-controller" ./cmd/controller
ok "Binary installed: ${BIN_DIR}/jawaker-controller"


###############################################################################
# Configuration  [6/7]
###############################################################################
step 6 "Writing configuration"
SECRET_KEY=$(gen_secret)
ADMIN_PASS=$(gen_pass)
ADMIN_EMAIL="${JAWAKER_ADMIN_EMAIL:-admin@jawaker.local}"
DATABASE_URL="postgres://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}?sslmode=disable"

mkdir -p "${CONF_DIR}"
chmod 700 "${CONF_DIR}"

# Controller always binds loopback; Nginx proxies when domain/SSL is configured.
# Cloudflare Tunnel also requires loopback — cloudflared proxies http://127.0.0.1:PORT.
# Without SSL/Cloudflare it binds 0.0.0.0 so the port is directly reachable.
if $USE_SSL; then
    LISTEN_ADDR="127.0.0.1:${CONTROLLER_PORT}"
    COOKIE_SECURE="true"
    COOKIE_ALLOW_INSECURE="false"
elif ${USE_CLOUDFLARE:-false}; then
    LISTEN_ADDR="127.0.0.1:${PANEL_PORT}"
    COOKIE_SECURE="false"
    COOKIE_ALLOW_INSECURE="true"
else
    LISTEN_ADDR=":${PANEL_PORT}"
    COOKIE_SECURE="false"
    COOKIE_ALLOW_INSECURE="true"
fi

cat >"${CONF_DIR}/jawaker.env" <<EOF
# JAWAKER Panel configuration — generated by install.sh
# To change any value: edit this file and run:
#   systemctl restart jawaker-controller
# To change the port (no-domain mode): update JAWAKER_LISTEN_ADDR and reload.

JAWAKER_DATABASE_URL=${DATABASE_URL}
JAWAKER_SECRET_KEY_V1=${SECRET_KEY}
JAWAKER_LISTEN_ADDR=${LISTEN_ADDR}
JAWAKER_RUN_MIGRATIONS=true
JAWAKER_COOKIE_SECURE=${COOKIE_SECURE}
JAWAKER_COOKIE_ALLOW_INSECURE=${COOKIE_ALLOW_INSECURE}
JAWAKER_LOG_LEVEL=info
JAWAKER_LOG_FORMAT=json
JAWAKER_BOOTSTRAP_ADMIN_EMAIL=${ADMIN_EMAIL}
JAWAKER_BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PASS}
EOF
chmod 600 "${CONF_DIR}/jawaker.env"
ok "Configuration written to ${CONF_DIR}/jawaker.env"

###############################################################################
# Systemd service & SSL  [7/7]
###############################################################################
step 7 "Starting services"
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
ok "Service ${SERVICE} started"

###############################################################################
# SSL + Nginx reverse proxy (only when domain is provided)
###############################################################################
if $USE_SSL; then
    info "Obtaining Let's Encrypt SSL certificate for ${DOMAIN}..."

    # Temporarily stop nginx if running (port 80 must be free for standalone challenge)
    systemctl stop nginx 2>/dev/null || true

    certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --email "${SSL_EMAIL}" \
        -d "${DOMAIN}" \
        --quiet

    ok "SSL certificate obtained"

    # Write Nginx vhost
    NGINX_CONF="/etc/nginx/sites-available/jawaker"
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

    cat >"${NGINX_CONF}" <<NGINX
# JAWAKER Panel — generated by install.sh
# Managed by: edit + nginx -t && systemctl reload nginx

server {
    listen 80;
    server_name ${DOMAIN};
    # Redirect HTTP → HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;
    add_header Strict-Transport-Security "max-age=63072000" always;

    # WebSocket support (terminal, SSE)
    location / {
        proxy_pass         http://127.0.0.1:${CONTROLLER_PORT};
        proxy_http_version 1.1;
        proxy_set_header   Upgrade \$http_upgrade;
        proxy_set_header   Connection \$connection_upgrade;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering    off;
    }
}
NGINX

    # Nginx map block for upgrade header (add to http context if not present)
    HTTP_CONF="/etc/nginx/conf.d/jawaker-upgrade.conf"
    if ! grep -q "connection_upgrade" /etc/nginx/nginx.conf 2>/dev/null; then
        cat >"${HTTP_CONF}" <<'MAP'
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
MAP
    fi

    # Enable site (Debian/Ubuntu style; RHEL uses conf.d directly)
    if [ -d /etc/nginx/sites-enabled ]; then
        ln -sf "${NGINX_CONF}" /etc/nginx/sites-enabled/jawaker
        # Disable default vhost if present (it conflicts on port 80)
        rm -f /etc/nginx/sites-enabled/default
    else
        # RHEL: copy to conf.d
        cp "${NGINX_CONF}" /etc/nginx/conf.d/jawaker.conf
    fi

    nginx -t && systemctl enable --now nginx
    ok "Nginx started with SSL for ${DOMAIN}"

    # Auto-renewal via systemd timer (preferred) or cron fallback
    if systemctl list-timers --all | grep -q certbot; then
        ok "Certbot auto-renewal timer already active"
    else
        # Add cron job: renew twice daily (Let's Encrypt recommendation)
        CRON_LINE="0 3,15 * * * root certbot renew --quiet --deploy-hook 'systemctl reload nginx'"
        if ! grep -qF "certbot renew" /etc/crontab 2>/dev/null; then
            echo "${CRON_LINE}" >> /etc/crontab
            ok "Auto-renewal cron installed (runs at 03:00 and 15:00)"
        else
            ok "Auto-renewal cron already present"
        fi
    fi
fi

###############################################################################
# Cloudflare Tunnel setup (only when user chose option 3)
###############################################################################
CF_URL=""
if ${USE_CLOUDFLARE:-false}; then
    info "Setting up Cloudflare Tunnel (no port opening needed)..."
    _CF_ARCH="amd64"
    [ "$(uname -m)" = "aarch64" ] && _CF_ARCH="arm64"
    CF_BIN="/usr/local/bin/cloudflared"
    if ! command -v cloudflared &>/dev/null; then
        info "Downloading cloudflared..."
        curl -sSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${_CF_ARCH}" -o "${CF_BIN}"
        chmod +x "${CF_BIN}"
        ok "cloudflared installed"
    fi

    cat >/etc/systemd/system/jawaker-tunnel.service <<EOF
[Unit]
Description=JAWAKER Cloudflare Quick Tunnel
After=network.target jawaker-controller.service
Wants=jawaker-controller.service

[Service]
Type=simple
User=root
# Wait briefly for the controller to bind before cloudflared tries to proxy it
ExecStartPre=/bin/sleep 3
ExecStart=${CF_BIN} tunnel --url http://127.0.0.1:${PANEL_PORT}
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=jawaker-tunnel

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable jawaker-tunnel

    # Give controller time to start before tunnel tries to connect
    info "Waiting for controller to be ready..."
    sleep 8

    systemctl start jawaker-tunnel && ok "Cloudflare Tunnel service started" || \
        warn "Tunnel service failed to start — retrying in 5s..."
    sleep 5
    systemctl is-active --quiet jawaker-tunnel || systemctl restart jawaker-tunnel || true

    info "Waiting for public Cloudflare HTTPS URL (this takes ~10 seconds)..."
    for _i in $(seq 1 12); do
        sleep 2
        CF_URL=$(journalctl -u jawaker-tunnel -n 50 --no-pager 2>/dev/null \
            | grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -1 || true)
        [ -n "$CF_URL" ] && break
    done
    if [ -n "$CF_URL" ]; then
        ok "Cloudflare URL: ${CF_URL}"
    else
        CF_URL="check: journalctl -u jawaker-tunnel | grep trycloudflare"
        warn "Tunnel URL not yet ready. ${CF_URL}"
    fi
fi

###############################################################################
# Wait for service to be healthy
###############################################################################
info "Waiting for JAWAKER to initialize..."
sleep 5
if systemctl is-active --quiet ${SERVICE}; then
    ok "Service is running"
else
    warn "Service may not be running — check: journalctl -u ${SERVICE} -n 50"
fi

###############################################################################
# Done — print access info
###############################################################################
echo ""
bold "╔══════════════════════════════════════════════════════╗"
bold "║              JAWAKER Panel is ready! 🎉              ║"
bold "╠══════════════════════════════════════════════════════╣"
bold "║                                                      ║"
if ${USE_CLOUDFLARE:-false} && [ -n "$CF_URL" ]; then
    printf  "║  URL:      \033[1m%-42s\033[0m║\n" "${CF_URL}"
    bold "║  Tunnel:   Cloudflare Quick Tunnel (free HTTPS)      ║"
elif $USE_SSL; then
    printf  "║  URL:      \033[1mhttps://%-35s\033[0m║\n" "${DOMAIN}/"
else
    IP=$(server_ip)
    printf  "║  URL:      \033[1mhttp://%-36s\033[0m║\n" "${IP}:${PANEL_PORT}/"
fi
printf  "║  Email:    %-42s║\n" "${ADMIN_EMAIL}"
printf  "║  Password: \033[1m%-42s\033[0m║\n" "${ADMIN_PASS}"
bold "║                                                      ║"
bold "║  Config:   /etc/jawaker/jawaker.env                  ║"
bold "║  Logs:     journalctl -u jawaker-controller -f       ║"
if $USE_SSL; then
bold "║  SSL:      auto-renews via cron (certbot renew)      ║"
fi
if ${USE_CLOUDFLARE:-false}; then
bold "║  Tunnel:   systemctl status jawaker-tunnel            ║"
fi
bold "║                                                      ║"
bold "╚══════════════════════════════════════════════════════╝"
echo ""
warn "Save your admin password now — it will not be shown again!"
if ! $USE_SSL && ! ${USE_CLOUDFLARE:-false}; then
    echo ""
    warn "If the panel is not reachable, open port ${PANEL_PORT} in your cloud provider"
    warn "firewall/Security Group (Linode, DigitalOcean, AWS, GCP, etc.):"
    warn "  Linode:         Linodes → Firewall → Add Inbound Rule → TCP ${PANEL_PORT}"
    warn "  DigitalOcean:   Networking → Firewalls → Inbound → TCP ${PANEL_PORT}"
    warn "  AWS EC2:        Security Groups → Inbound Rules → TCP ${PANEL_PORT}"
fi
echo ""

