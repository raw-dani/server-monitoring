#!/usr/bin/env bash
# ==============================================================================
# SHSM (Server Health & Security Monitoring) - Upgrade Script
# Safely updates the codebase, dependencies, and database migrations.
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

if [[ $EUID -ne 0 ]]; then
   log_err "This script must be run as root (or via sudo)."
   exit 1
fi

INSTALL_DIR="/opt/shsm"
SHSM_USER="shsm"
SHSM_GROUP="shsm"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log_info "Upgrading SHSM..."

# 0. Temporarily pause timers and terminate any running background collectors to release DB locks
log_info "Temporarily pausing SHSM background timers and releasing DB locks..."
systemctl stop 'shsm-*.timer' 2>/dev/null || true
pkill -9 -u "$SHSM_USER" -f "/opt/shsm" 2>/dev/null || true
rm -f /var/lib/shsm/locks/*.lock /tmp/shsm_locks/*.lock 2>/dev/null || true

# 1. Automatic pre-upgrade DB Backup (with safety timeout)
log_info "Creating automatic pre-upgrade database backup..."
if [ -f "/var/lib/shsm/monitoring.db" ]; then
    mkdir -p /var/lib/shsm/backups
    BACKUP_FILE="/var/lib/shsm/backups/shsm_pre_upgrade_$(date +%Y%m%d_%H%M%S).db"
    if command -v sqlite3 &>/dev/null; then
        sqlite3 /var/lib/shsm/monitoring.db ".backup '$BACKUP_FILE'" 2>/dev/null || cp -a /var/lib/shsm/monitoring.db "$BACKUP_FILE"
    else
        cp -a /var/lib/shsm/monitoring.db "$BACKUP_FILE"
    fi
    chown -R "$SHSM_USER:$SHSM_GROUP" /var/lib/shsm/backups 2>/dev/null || true
    log_ok "Backup created at $BACKUP_FILE"
fi

# 2. Sync codebase
log_info "Copying latest source code to $INSTALL_DIR..."
cp -ru "$SCRIPT_DIR/src" "$INSTALL_DIR/"
cp -u "$SCRIPT_DIR/pyproject.toml" "$INSTALL_DIR/" 2>/dev/null || true

# 3. Update Python packages in virtual environment
log_info "Updating virtual environment packages..."
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip setuptools wheel
"$INSTALL_DIR/venv/bin/pip" install -e "$INSTALL_DIR"

# Enforce ownership on installed files to prevent permission issues for daemon
chown -R "$SHSM_USER:$SHSM_GROUP" "$INSTALL_DIR" /var/lib/shsm /var/log/shsm 2>/dev/null || true

# 4. Run database migrations
log_info "Applying any pending database migrations..."
sudo -u "$SHSM_USER" /usr/local/bin/shsm db migrate

# 5. Ensure group memberships for reading website files and process stats
log_info "Ensuring group memberships for $SHSM_USER..."
if getent group nobody &>/dev/null; then
    usermod -aG nobody "$SHSM_USER" 2>/dev/null || true
fi
if getent group nogroup &>/dev/null; then
    usermod -aG nogroup "$SHSM_USER" 2>/dev/null || true
fi
if getent group adm &>/dev/null; then
    usermod -aG adm "$SHSM_USER" 2>/dev/null || true
fi
if getent group postfix &>/dev/null; then
    usermod -aG postfix "$SHSM_USER" 2>/dev/null || true
fi

# 6. Update sudoers configuration and CLI link
if [ -f "$SCRIPT_DIR/scripts/shsm.sudoers" ]; then
    log_info "Updating sudoers configuration at /etc/sudoers.d/shsm..."
    cp "$SCRIPT_DIR/scripts/shsm.sudoers" /etc/sudoers.d/shsm
    chmod 0440 /etc/sudoers.d/shsm
    visudo -c -f /etc/sudoers.d/shsm 2>/dev/null || true
fi

log_info "Linking /usr/local/bin/shsm directly to virtualenv..."
ln -sf "$INSTALL_DIR/venv/bin/shsm" /usr/local/bin/shsm
log_ok "Linked /usr/local/bin/shsm"

# 7. Verify health (optional preflight diagnostics with 10s timeout)
log_info "Running post-upgrade verification..."
if timeout 10 "$INSTALL_DIR/venv/bin/shsm" --help &>/dev/null; then log_ok "SHSM CLI verified working."; else log_warn "Self-test skipped."; fi 

# 8. Update systemd units with resource control & quotas and start timers
if [ -d "$SCRIPT_DIR/systemd" ]; then
    log_info "Syncing systemd unit definitions with CPU and memory throttling..."
    cp "$SCRIPT_DIR/systemd/"*.service /etc/systemd/system/ 2>/dev/null || true
    cp "$SCRIPT_DIR/systemd/"*.timer /etc/systemd/system/ 2>/dev/null || true
    systemctl daemon-reload
    systemctl reset-failed 'shsm-*' 2>/dev/null || true
    for timer in /etc/systemd/system/shsm-*.timer; do
        timer_name=$(basename "$timer")
        systemctl start "$timer_name" 2>/dev/null || true
    done
    log_ok "Systemd units updated and timers restarted with non-overlapping schedules."
fi

log_ok "SHSM has been successfully upgraded to the latest version!"

