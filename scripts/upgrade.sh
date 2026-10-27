#!/usr/bin/env bash
# ==============================================================================
# SHSM (Server Health & Security Monitoring) - Upgrade Script
# Safely updates the codebase, dependencies, and database migrations.
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

if [[ $EUID -ne 0 ]]; then
   log_err "This script must be run as root (or via sudo)."
   exit 1
fi

INSTALL_DIR="/opt/shsm"
SHSM_USER="shsm"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log_info "Upgrading SHSM..."

# 1. Automatic pre-upgrade DB Backup
log_info "Creating automatic pre-upgrade database backup..."
if command -v shsm &>/dev/null; then
    sudo -u "$SHSM_USER" shsm db backup || log_err "Warning: pre-upgrade DB backup failed."
fi

# 2. Sync codebase
log_info "Copying latest source code to $INSTALL_DIR..."
cp -ru "$SCRIPT_DIR/src" "$INSTALL_DIR/"
cp -u "$SCRIPT_DIR/pyproject.toml" "$INSTALL_DIR/" 2>/dev/null || true

# 3. Update Python packages in virtual environment
log_info "Updating virtual environment packages..."
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip setuptools wheel
"$INSTALL_DIR/venv/bin/pip" install -e "$INSTALL_DIR"

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

# 6. Update sudoers configuration and CLI wrapper
if [ -f "$SCRIPT_DIR/scripts/shsm.sudoers" ]; then
    log_info "Updating sudoers configuration at /etc/sudoers.d/shsm..."
    cp "$SCRIPT_DIR/scripts/shsm.sudoers" /etc/sudoers.d/shsm
    chmod 0440 /etc/sudoers.d/shsm
    visudo -c -f /etc/sudoers.d/shsm 2>/dev/null || true
fi

if [ -f "$SCRIPT_DIR/scripts/shsm-wrapper.sh" ]; then
    log_info "Installing auto-switch CLI wrapper to /usr/local/bin/shsm..."
    cp "$SCRIPT_DIR/scripts/shsm-wrapper.sh" /usr/local/bin/shsm
    chmod 0755 /usr/local/bin/shsm
    log_ok "CLI wrapper installed (enables running 'shsm' directly without 'sudo -u shsm')."
fi

# 7. Update systemd units with resource control & quotas
if [ -d "$SCRIPT_DIR/systemd" ]; then
    log_info "Syncing systemd unit definitions with CPU and memory throttling..."
    cp "$SCRIPT_DIR/systemd/"*.service /etc/systemd/system/ 2>/dev/null || true
    cp "$SCRIPT_DIR/systemd/"*.timer /etc/systemd/system/ 2>/dev/null || true
    systemctl daemon-reload
    log_ok "Systemd units updated with CPU quotas and reloaded."
fi

# 8. Verify health
log_info "Running post-upgrade self-test..."
/usr/local/bin/shsm doctor

log_ok "SHSM has been successfully upgraded to the latest version!"

