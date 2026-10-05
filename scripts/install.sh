#!/usr/bin/env bash
# ==============================================================================
# SHSM (Server Health & Security Monitoring) - Production Installation Script
# Target: Ubuntu 20.04+ LTS VPS (CyberPanel, OpenLiteSpeed, WordPress)
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

log_info "Starting SHSM Installation..."

# 1. Preflight checks
log_info "Performing preflight checks..."
if ! grep -qi "ubuntu" /etc/os-release; then
    log_warn "Target OS is not explicitly Ubuntu. Proceeding with caution..."
fi

# Check Python 3.9+
PYTHON_BIN=""
for cmd in python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$cmd" &>/dev/null; then
        VER=$($cmd -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        MAJOR=$(echo "$VER" | cut -d. -f1)
        MINOR=$(echo "$VER" | cut -d. -f2)
        if [ "$MAJOR" -eq 3 ] && [ "$MINOR" -ge 9 ]; then
            PYTHON_BIN="$cmd"
            log_ok "Found compatible Python: $cmd ($VER)"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    log_err "Python 3.9 or higher is required. Please install python3.9+ and python3-venv."
    exit 1
fi

# Ensure python3-venv is available
if ! $PYTHON_BIN -m venv --help &>/dev/null; then
    log_err "Python venv module is missing. Run: apt-get install -y python3-venv"
    exit 1
fi

# Optional tools check
for tool in ufw fail2ban-client wp lynis rkhunter clamscan; do
    if command -v "$tool" &>/dev/null; then
        log_ok "Detected tool: $tool"
    else
        log_warn "Optional tool '$tool' not found in PATH. Relevant security checks will gracefully record UNAVAILABLE."
    fi
done

# 2. Setup Dedicated User & Group
SHSM_USER="shsm"
SHSM_GROUP="shsm"

# Clean stale lock files if any
rm -f /etc/passwd.lock /etc/shadow.lock /etc/group.lock /etc/gshadow.lock /etc/.pwd.lock 2>/dev/null || true

# Check and temporarily remove immutable attribute if set by security hardening
WAS_PASSWD_IMMUTABLE=false
if command -v lsattr &>/dev/null && command -v chattr &>/dev/null; then
    if lsattr /etc/passwd 2>/dev/null | grep -q -- "-i-"; then
        log_warn "Detected immutable attribute (+i) on /etc/passwd. Temporarily unlocking..."
        chattr -i /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null || true
        WAS_PASSWD_IMMUTABLE=true
    fi
fi

if ! getent group "$SHSM_GROUP" &>/dev/null; then
    log_info "Creating group: $SHSM_GROUP"
    groupadd --system "$SHSM_GROUP"
fi

if ! id -u "$SHSM_USER" &>/dev/null; then
    log_info "Creating system user: $SHSM_USER"
    useradd --system --gid "$SHSM_GROUP" --shell /bin/false --no-create-home "$SHSM_USER"
fi

# Restore immutable attribute if it was previously set
if [ "$WAS_PASSWD_IMMUTABLE" = true ] && command -v chattr &>/dev/null; then
    log_info "Restoring immutable attribute (+i) on /etc/passwd..."
    chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null || true
fi

# Add shsm to adm group to allow reading system logs if appropriate
usermod -aG adm "$SHSM_USER" || true

# 3. Create Directory Structure
INSTALL_DIR="/opt/shsm"
DATA_DIR="/var/lib/shsm"
LOG_DIR="/var/log/shsm"
CONFIG_DIR="/etc/shsm"
REPORT_DIR="/var/lib/shsm/reports"
BACKUP_DIR="/var/lib/shsm/backups"

log_info "Creating required directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR" "$REPORT_DIR" "$BACKUP_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$CONFIG_DIR"

# 4. Copy Codebase & Create Virtualenv
log_info "Setting up virtual environment and copying files..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Copy src and setup
cp -ru "$SCRIPT_DIR/src" "$INSTALL_DIR/"
cp -u "$SCRIPT_DIR/pyproject.toml" "$INSTALL_DIR/" 2>/dev/null || true

# Create venv if not existing
if [ ! -d "$INSTALL_DIR/venv" ]; then
    log_info "Creating virtual environment at $INSTALL_DIR/venv..."
    $PYTHON_BIN -m venv "$INSTALL_DIR/venv"
fi

# Install dependencies and editable package
log_info "Installing Python dependencies..."
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip setuptools wheel
"$INSTALL_DIR/venv/bin/pip" install -e "$INSTALL_DIR"

# Symlink CLI binary to /usr/local/bin/shsm
ln -sf "$INSTALL_DIR/venv/bin/shsm" /usr/local/bin/shsm
log_ok "Linked /usr/local/bin/shsm"

# 5. Initialize Configuration if not exists
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    log_info "Initializing default config at $CONFIG_DIR/config.yaml..."
    if [ -f "$SCRIPT_DIR/config/config.example.yaml" ]; then
        cp "$SCRIPT_DIR/config/config.example.yaml" "$CONFIG_DIR/config.yaml"
    else
        log_warn "config.example.yaml not found, please configure $CONFIG_DIR/config.yaml manually."
    fi
fi

if [ ! -f "$CONFIG_DIR/thresholds.yaml" ] && [ -f "$SCRIPT_DIR/config/thresholds.example.yaml" ]; then
    cp "$SCRIPT_DIR/config/thresholds.example.yaml" "$CONFIG_DIR/thresholds.yaml"
fi

if [ ! -f "$CONFIG_DIR/paths.yaml" ] && [ -f "$SCRIPT_DIR/config/paths.example.yaml" ]; then
    cp "$SCRIPT_DIR/config/paths.example.yaml" "$CONFIG_DIR/paths.yaml"
fi

# 6. Sudoers file
if [ -f "$SCRIPT_DIR/scripts/shsm.sudoers" ]; then
    log_info "Installing sudoers configuration..."
    cp "$SCRIPT_DIR/scripts/shsm.sudoers" /etc/sudoers.d/shsm
    chmod 0440 /etc/sudoers.d/shsm
    visudo -c -f /etc/sudoers.d/shsm
    log_ok "Sudoers file validated and installed."
fi

# 7. Apply Permissions (Strict Principle of Least Privilege)
log_info "Enforcing strict filesystem permissions..."
chown -R "$SHSM_USER:$SHSM_GROUP" "$DATA_DIR" "$LOG_DIR" "$INSTALL_DIR"
chown -R root:"$SHSM_GROUP" "$CONFIG_DIR"

chmod 0750 "$DATA_DIR" "$LOG_DIR"
chmod 0750 "$CONFIG_DIR"
find "$CONFIG_DIR" -type f -exec chmod 0640 {} +

# 8. Run Database Migrations
log_info "Running initial SQLite database migrations..."
sudo -u "$SHSM_USER" /usr/local/bin/shsm db migrate || {
    log_err "Database migration failed."
    exit 1
}
log_ok "Database migrations completed successfully."

# 9. Install and Enable Systemd Timers
log_info "Installing systemd units and timers..."
if [ -d "$SCRIPT_DIR/systemd" ]; then
    cp "$SCRIPT_DIR/systemd/"*.service /etc/systemd/system/
    cp "$SCRIPT_DIR/systemd/"*.timer /etc/systemd/system/
    systemctl daemon-reload

    log_info "Enabling all 21 SHSM timers..."
    for timer in /etc/systemd/system/shsm-*.timer; do
        timer_name=$(basename "$timer")
        systemctl enable --now "$timer_name"
    done
    log_ok "All systemd timers enabled and started."
else
    log_warn "Systemd directory not found. Please run 'shsm schedule install' or generate units."
fi

# 10. Run Self-Test
log_info "Executing self-test verification..."
/usr/local/bin/shsm doctor || log_warn "Self-test finished with warnings. Please review the output above."

log_ok "=================================================================="
log_ok " SHSM Installation Completed Successfully!"
log_ok " Configuration:  $CONFIG_DIR/config.yaml"
log_ok " Database:       $DATA_DIR/monitoring.db"
log_ok " Logs:           $LOG_DIR/shsm.log"
log_ok " CLI:            shsm --help"
log_ok " System Timers:  systemctl list-timers 'shsm-*'"
log_ok "=================================================================="
