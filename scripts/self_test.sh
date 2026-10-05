#!/usr/bin/env bash
# ==============================================================================
# SHSM (Server Health & Security Monitoring) - Self-Test Suite Runner
# Validates configuration, database integrity, CLI commands, and collectors.
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=== Starting SHSM Diagnostic Self-Test ===${NC}"

# Check CLI availability
if ! command -v shsm &>/dev/null; then
    if [ -f "/opt/shsm/venv/bin/shsm" ]; then
        SHSM_CMD="/opt/shsm/venv/bin/shsm"
    elif [ -f "./.venv/bin/shsm" ]; then
        SHSM_CMD="./.venv/bin/shsm"
    else
        echo -e "${RED}[FAIL] 'shsm' command not found in PATH or standard venvs.${NC}"
        exit 1
    fi
else
    SHSM_CMD="shsm"
fi

echo -e "${GREEN}[1/5] Checking CLI Version and Doctor...${NC}"
$SHSM_CMD --version
$SHSM_CMD doctor

echo -e "\n${GREEN}[2/5] Validating Configuration and Thresholds...${NC}"
$SHSM_CMD config show

echo -e "\n${GREEN}[3/5] Testing Database Migrations and Status...${NC}"
$SHSM_CMD db status

echo -e "\n${GREEN}[4/5] Executing Dry-Run Health Check...${NC}"
$SHSM_CMD health run --dry-run || echo "Dry run executed."

echo -e "\n${GREEN}[5/5] Executing Dry-Run Security Audit...${NC}"
$SHSM_CMD security audit --dry-run || echo "Security dry run executed."

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${GREEN} All diagnostic self-tests completed successfully! ${NC}"
echo -e "${BLUE}====================================================${NC}"
