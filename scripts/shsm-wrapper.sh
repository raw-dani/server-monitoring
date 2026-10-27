#!/usr/bin/env bash
# SHSM Auto-Switch User Wrapper
# Automatically drops root privileges to 'shsm' system user to preserve database
# permissions and adhere to the principle of least privilege.

SHSM_BIN="/opt/shsm/venv/bin/shsm"

if [ ! -x "$SHSM_BIN" ]; then
    echo "[ERROR] SHSM binary not found at $SHSM_BIN" >&2
    exit 1
fi

# 1. If executed by root, automatically switch to 'shsm' user
if [ "$(id -u)" -eq 0 ]; then
    exec su -s /bin/bash shsm -c "$SHSM_BIN \"\$@\"" -- "$@"

# 2. If already executed as 'shsm' user, run directly
elif [ "$(id -un)" = "shsm" ]; then
    exec "$SHSM_BIN" "$@"

# 3. If executed by normal user with sudo privileges, invoke via sudo
else
    exec sudo -u shsm "$SHSM_BIN" "$@"
fi
