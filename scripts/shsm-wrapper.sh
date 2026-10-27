#!/usr/bin/env bash
# SHSM Auto-Switch User Wrapper
# Automatically drops root privileges to 'shsm' system user to preserve database
# permissions and adhere to the principle of least privilege.

SHSM_BIN="/opt/shsm/venv/bin/shsm"

if [ ! -x "$SHSM_BIN" ]; then
    echo "[ERROR] SHSM binary not found at $SHSM_BIN" >&2
    exit 1
fi

# If already executed as 'shsm' user, run directly
if [ "$(id -un)" = "shsm" ]; then
    exec "$SHSM_BIN" "$@"
fi

# If executed by root, invoke under shsm via sudo or su
if [ "$(id -u)" -eq 0 ]; then
    if command -v sudo &>/dev/null; then
        exec sudo -u shsm -H "$SHSM_BIN" "$@"
    else
        exec su -s /bin/bash shsm -c '"$0" "$@"' "$SHSM_BIN" "$@"
    fi
else
    # If executed by normal user with sudo privileges, invoke via sudo
    exec sudo -u shsm -H "$SHSM_BIN" "$@"
fi
