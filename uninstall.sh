#!/usr/bin/env bash
# JAWAKER Panel — Uninstaller
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/bukansembarangkong/jawaker-panel/main/uninstall.sh | bash
#   bash /opt/jawaker-panel/uninstall.sh [OPTIONS]
#
# Options:
#   --purge-db    Drop jawaker database and database user (destructive)
#   --force       Skip confirmation prompts
#   -h, --help    Show help
#
set -euo pipefail

BOLD='\033[1m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { printf "${BLUE}[jawaker] %s${NC}\n" "$*"; }
ok()   { printf "${GREEN}[jawaker] ✓ %s${NC}\n" "$*"; }
warn() { printf "${YELLOW}[jawaker] ⚠ %s${NC}\n" "$*"; }
err()  { printf "${RED}[jawaker] ✗ %s${NC}\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash uninstall.sh"

PURGE_DB=false
FORCE=false

for arg in "$@"; do
    case "${arg}" in
        --purge-db) PURGE_DB=true ;;
        --force|-f) FORCE=true ;;
        -h|--help)
            echo "JAWAKER Panel Uninstaller"
            echo ""
            echo "Usage: bash uninstall.sh [options]"
            echo ""
            echo "Options:"
            echo "  --purge-db   Drop the jawaker_panel PostgreSQL database and jawaker user"
            echo "  --force, -f  Non-interactive, skip confirmation"
            echo "  -h, --help   Show this help message"
            exit 0
            ;;
    esac
done

# Connect TTY for curl | bash
TTY_IN="/dev/stdin"
if [ ! -t 0 ] && [ -r /dev/tty ]; then
    TTY_IN="/dev/tty"
fi

echo ""
printf "${BOLD}${RED}╔════════════════════════════════════════════════════════╗${NC}\n"
printf "${BOLD}${RED}║            JAWAKER PANEL UNINSTALLATION                ║${NC}\n"
printf "${BOLD}${RED}╚════════════════════════════════════════════════════════╝${NC}\n"
echo ""

if ! $FORCE; then
    warn "This will remove JAWAKER services, binaries, and configurations."
    printf "Are you sure you want to uninstall JAWAKER Panel? [y/N]: "
    read -r CONFIRM < "${TTY_IN}" || CONFIRM="n"
    case "${CONFIRM}" in
        [yY][eE][sS]|[yY]) ;;
        *) info "Uninstallation aborted."; exit 0 ;;
    esac

    if ! $PURGE_DB; then
        echo ""
        printf "Do you also want to DELETE the PostgreSQL database (jawaker_panel)? [y/N]: "
        read -r DB_CONFIRM < "${TTY_IN}" || DB_CONFIRM="n"
        case "${DB_CONFIRM}" in
            [yY][eE][sS]|[yY]) PURGE_DB=true ;;
        esac
    fi
fi

echo ""
info "Stopping and removing services..."

# 1. Stop and disable systemd services
for svc in jawaker-controller jawaker-tunnel; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
        systemctl stop "${svc}" && ok "Stopped ${svc}" || warn "Could not stop ${svc}"
    fi
    if systemctl is-enabled --quiet "${svc}" 2>/dev/null; then
        systemctl disable "${svc}" 2>/dev/null && ok "Disabled ${svc}" || true
    fi
    rm -f "/etc/systemd/system/${svc}.service"
done
systemctl daemon-reload

# 2. Remove binaries
info "Removing binaries..."
rm -f /usr/local/bin/jawaker-controller
ok "Removed /usr/local/bin/jawaker-controller"

# 3. Clean up Cloudflare tunnel binary if installed
if [ -f /usr/local/bin/cloudflared ]; then
    rm -f /usr/local/bin/cloudflared
    ok "Removed /usr/local/bin/cloudflared"
fi

# 4. Remove Nginx configuration
info "Cleaning up web server configuration..."
rm -f /etc/nginx/sites-enabled/jawaker
rm -f /etc/nginx/sites-available/jawaker
rm -f /etc/nginx/conf.d/jawaker.conf
rm -f /etc/nginx/conf.d/jawaker-upgrade.conf
if command -v nginx &>/dev/null; then
    nginx -t &>/dev/null && systemctl reload nginx 2>/dev/null || true
fi
ok "Cleaned Nginx configurations"

# 5. Remove crontab certbot hook if present
if [ -f /etc/crontab ]; then
    sed -i '/certbot renew.*jawaker/d' /etc/crontab 2>/dev/null || true
fi

# 6. Database cleanup
if $PURGE_DB; then
    info "Purging database and user..."
    if command -v su &>/dev/null && id -u postgres &>/dev/null; then
        su - postgres -c "psql -c 'DROP DATABASE IF EXISTS jawaker_panel;'" 2>/dev/null || true
        su - postgres -c "psql -c 'DROP USER IF EXISTS jawaker;'" 2>/dev/null || true
        ok "Dropped PostgreSQL database and user"
    else
        warn "Could not access postgres user to drop database"
    fi
else
    info "Preserved database (jawaker_panel). Use --purge-db to remove it."
fi

# 7. Remove configuration files
info "Removing configuration files..."
rm -rf /etc/jawaker
ok "Removed /etc/jawaker"

# 8. Remove repository directory
info "Removing application files..."
rm -rf /opt/jawaker-panel
ok "Removed /opt/jawaker-panel"

echo ""
printf "${GREEN}${BOLD}✓ JAWAKER Panel has been successfully uninstalled.${NC}\n"
echo ""
