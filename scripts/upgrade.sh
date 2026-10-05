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

# 5. Update systemd units if changed
if [ -d "$SCRIPT_DIR/systemd" ]; then
    log_info "Syncing systemd unit definitions..."
    cp -u "$SCRIPT_DIR/systemd/"*.service /etc/systemd/system/ 2>/dev/null || true
    cp -u "$SCRIPT_DIR/systemd/"*.timer /etc/systemd/system/ 2>/dev/null || true
    systemctl daemon-reload
fi

# 6. Verify health
log_info "Running post-upgrade self-test..."
/usr/local/bin/shsm doctor

log_ok "SHSM has been successfully upgraded to the latest version!"
