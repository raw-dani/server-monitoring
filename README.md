# Server Health & Security Monitoring (SHSM)

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: Proprietary](https://img.shields.io/badge/license-Proprietary-green.svg)]()
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: mypy](https://img.shields.io/badge/mypy-checked-blue.svg)](http://mypy-lang.org/)

**SHSM** is an enterprise-grade, lightweight, strictly read-only Command Line Interface (CLI) monitoring suite designed for production Ubuntu 20.04+ LTS VPS hosting **CyberPanel**, **OpenLiteSpeed (OLS)**, **MariaDB**, **Redis**, and multiple **WordPress** installations.

---

## Key Highlights

- **Strictly Read-Only & Non-Destructive**: Zero automatic remediation. SHSM observes, analyzes, diagnoses, alerts, and reports without risking service restarts or unintended configuration changes.
- **Principle of Least Privilege**: Dedicated `shsm` system account. WP-CLI commands are strictly invoked as each website's Linux owner (never as root).
- **Comprehensive Subsystem Coverage**:
  - **Health**: CPU & load, Memory & Swap (OOM detection), Disk & Inodes, Services & Flapping, Database (MariaDB & Redis), Web & SSL (HTTP latency & TLS certificate expiry).
  - **Security**: SSH security & login baselining, Firewall & Fail2Ban, WordPress core checksums & admin discovery, Malware heuristics & ClamAV, Lynis & Rootkit scanners, File Integrity Monitoring (FIM).
- **Deterministic 0–100 Scoring**: Health and Security scores calculated using weighted subsystems with strict freshness and coverage tracking.
- **Automated Scheduling**: 21 individual, isolated systemd timers (`Persistent=true`). Zero permanent background daemons.
- **Reporting & Notifications**:
  - HTML email alerts with secret redaction.
  - Comprehensive Weekly and Monthly PDF reports compiled natively using ReportLab.
  - Heartbeat webhook integration with Uptime Kuma and generic HTTPS endpoints.

---

## Architecture Overview

```
                      +-----------------------------+
                      |   21 Systemd Timers/CLI     |
                      +--------------+--------------+
                                     |
                                     v
                       +---------------------------+
                       |      Runner Engine        |
                       |  (Locking, Runs, Scopes)  |
                       +-------------+-------------+
                                     |
         +---------------------------+---------------------------+
         |                                                       |
         v                                                       v
+------------------+                                   +------------------+
| Health Collectors|                                   |Security Scanners |
|  * CPU & Load    |                                   |  * SSH & Logins  |
|  * RAM & OOM     |                                   |  * Firewall/F2B  |
|  * Disk & Inodes |                                   |  * WP Integrity  |
|  * Services/OLS  |                                   |  * ClamAV/Lynis  |
|  * MariaDB/Redis |                                   |  * Rootkits/FIM  |
|  * Web & SSL     |                                   |  * Vulnerability |
+--------+---------+                                   +--------+---------+
         |                                                       |
         +---------------------------+---------------------------+
                                     |
                                     v
                      +-----------------------------+
                      | SQLite (WAL, Foreign Keys)  |
                      |   /var/lib/shsm/monitoring  |
                      +--------------+--------------+
                                     |
         +---------------------------+---------------------------+
         |                                                       |
         v                                                       v
+------------------+                                   +------------------+
|   Scoring Engine |                                   |   Notifications  |
|  * Health (0-100)|                                   |  * Cooldowns     |
|  * Sec (0-100)   |                                   |  * Redacted SMTP |
|  * Coverage %    |                                   |  * ReportLab PDF |
+------------------+                                   +------------------+
```

---

## Directory Structure

```
d:/Server/server-monitoring/
├── config/                     # Example and template configurations
│   ├── config.example.yaml
│   ├── paths.example.yaml
│   └── thresholds.example.yaml
├── docs/                       # Comprehensive documentation guides
│   ├── BACKUP_RESTORE.md
│   ├── CONFIGURATION.md
│   ├── EXTERNAL_MONITORING.md
│   ├── INSTALLATION.md
│   ├── OPERATIONS.md
│   ├── SECURITY.md
│   └── TROUBLESHOOTING.md
├── scripts/                    # Deployment and management shell scripts
│   ├── install.sh
│   ├── self_test.sh
│   ├── shsm.sudoers
│   ├── uninstall.sh
│   └── upgrade.sh
├── src/shsm/                   # Core Python application package
│   ├── collectors/             # System health collectors (CPU, RAM, Disk, DB, etc.)
│   ├── core/                   # Context, findings, locks, runner, timeutils
│   ├── database/               # SQLite connection, migrations, repositories
│   ├── deploy/                 # Systemd unit generator and scheduling
│   ├── discovery/              # CyberPanel and WordPress discovery
│   ├── notifications/          # Alert manager, SMTP transport, external push
│   ├── reporting/              # Scoring engine, HTML and ReportLab PDF reports
│   ├── security/               # SSH, WP integrity, ClamAV, Lynis, Rootkits, FIM
│   ├── utils/                  # Safe subprocesses, logtail, redaction, fs helpers
│   ├── cli.py                  # Click CLI entrypoint
│   └── config.py               # Configuration parser and schema validation
├── systemd/                    # 42 generated systemd service and timer unit files
├── tests/                      # Automated test suite (unit + integration)
│   ├── conftest.py
│   ├── integration/
│   └── unit/
└── pyproject.toml              # Build definition and dependencies
```

---

## CLI Cheatsheet

| Command | Description |
| :--- | :--- |
| `sudo -u shsm shsm status` | Display server health, security scores, subsystems, and active findings |
| `sudo -u shsm shsm doctor` | Run comprehensive system diagnostic checks |
| `sudo -u shsm shsm collect health` | Collect CPU, RAM, swap, and disk metrics |
| `sudo -u shsm shsm collect services` | Check OpenLiteSpeed, MariaDB, Redis, SSH, Cron, and failed units |
| `sudo -u shsm shsm collect databases` | Collect MariaDB uptime, connection rates, slow queries, and Redis metrics |
| `sudo -u shsm shsm security audit` | Execute security scans across SSH config/logs, firewall, and Fail2Ban |
| `sudo -u shsm shsm security scan --profile quick` | Run fast heuristic malware scans on uploads and executable PHP scripts |
| `sudo -u shsm shsm security scan --profile full` | Run comprehensive deep security scan (ClamAV, Rootkits, Lynis) |
| `sudo -u shsm shsm websites discover` | Discover websites from CyberPanel database, OLS vhosts, and `/home` |
| `sudo -u shsm shsm websites check` | Check website DNS, HTTP response times, and SSL certificate expiration |
| `sudo -u shsm shsm wordpress audit` | Audit WordPress core integrity, plugins, themes, and administrators |
| `sudo -u shsm shsm findings list` | View active open security and health findings |
| `sudo -u shsm shsm findings resolve <uid>` | Mark an issue as resolved (or `all-malware` / `all`) |
| `sudo -u shsm shsm integrity baseline --update` | Update cryptographic baseline for monitored system files (FIM) |
| `sudo -u shsm shsm report weekly --send` | Generate weekly HTML & ReportLab PDF report and dispatch via email |
| `sudo -u shsm shsm db backup` | Create atomic, consistent online SQLite backup |
| `systemctl list-timers 'shsm-*'` | Inspect state of all 21 systemd timers |

---

## Quickstart

### Prerequisites
- Ubuntu 20.04 LTS or newer.
- Python 3.9+ with `python3-venv`.
- CyberPanel with OpenLiteSpeed installed.

### Automated Installation
```bash
# Clone or copy repository to VPS
git clone https://github.com/raw-dani/server-monitoring.git /opt/shsm-src
cd /opt/shsm-src

# Run production installer (creates user 'shsm', venv, migrations, and timers)
sudo bash scripts/install.sh
```

### Verify Deployment
```bash
# Run self-test diagnostics
sudo -u shsm shsm doctor

# View current server score and findings
sudo -u shsm shsm status
```

For advanced configuration and operations, consult the [Documentation Index](docs/).
