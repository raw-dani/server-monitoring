#!/usr/bin/env bash
# ==============================================================================
# SHSM (Server Health & Security Monitoring) - Uninstall Script
# Safely disables timers, removes units, and optionally purges data.
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

if [[ $EUID -ne 0 ]]; then
   log_err "This script must be run as root (or via sudo)."
   exit 1
fi

PURGE_DATA=false
if [[ "${1:-}" == "--purge-data" ]]; then
    PURGE_DATA=true
    log_warn "Purge mode ENABLED: Database, reports, and logs will be permanently deleted."
fi

log_info "Stopping and disabling all SHSM systemd timers and services..."
for timer in /etc/systemd/system/shsm-*.timer; do
    if [ -f "$timer" ]; then
        tname=$(basename "$timer")
        systemctl stop "$tname" 2>/dev/null || true
        systemctl disable "$tname" 2>/dev/null || true
        rm -f "$timer"
    fi
done

for srv in /etc/systemd/system/shsm-*.service; do
    if [ -f "$srv" ]; then
        sname=$(basename "$srv")
        systemctl stop "$sname" 2>/dev/null || true
        systemctl disable "$sname" 2>/dev/null || true
        rm -f "$srv"
    fi
done

systemctl daemon-reload

log_info "Removing CLI symlink..."
rm -f /usr/local/bin/shsm

log_info "Removing sudoers rule..."
rm -f /etc/sudoers.d/shsm

log_info "Removing installation directory /opt/shsm..."
rm -rf /opt/shsm

if [ "$PURGE_DATA" = true ]; then
    log_warn "Deleting /var/lib/shsm, /var/log/shsm, and /etc/shsm..."
    rm -rf /var/lib/shsm
    rm -rf /var/log/shsm
    rm -rf /etc/shsm
    userdel shsm 2>/dev/null || true
    groupdel shsm 2>/dev/null || true
    log_ok "All data, logs, configuration, and system accounts purged."
else
    log_info "Preserving configuration (/etc/shsm), data (/var/lib/shsm), and logs (/var/log/shsm)."
    log_info "To completely remove all data, rerun with: $0 --purge-data"
fi

log_ok "SHSM has been successfully uninstalled."
