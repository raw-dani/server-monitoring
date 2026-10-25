# SHSM Installation Guide

This guide covers production deployment of **Server Health & Security Monitoring (SHSM)** on Ubuntu 20.04+ LTS VPS hosting CyberPanel, OpenLiteSpeed, MariaDB, and WordPress.

---

## 1. System Requirements

- **Operating System**: Ubuntu 20.04 LTS, 22.04 LTS, or 24.04 LTS.
- **Python**: Python 3.9, 3.10, 3.11, or 3.12 (with `python3-venv`).
- **Dependencies**: `git`, `systemd`, `sudo`, `sqlite3`.
- **Target Applications**:
  - CyberPanel (`/etc/cyberpanel/mysqlPassword`)
  - OpenLiteSpeed (`/usr/local/lsws/`)
  - MariaDB (`mariadb.service` / `/var/run/mysqld/mysqld.sock`)
  - Redis (`redis.service` / port 6379)
  - WP-CLI (`/usr/local/bin/wp`)
  - Firewall: CSF, Firewalld, UFW, or iptables

---

## 2. Security & Least Privilege Architecture

SHSM is designed from the ground up to follow the Principle of Least Privilege:
1. **Dedicated User**: Runs under system account `shsm` and group `shsm`.
2. **Sudoers Scope**: A strictly limited sudoers definition (`/etc/sudoers.d/shsm`) allows `shsm` to:
   - Run read-only diagnostics (`systemctl is-active`, `systemctl status`, `journalctl`, `ufw status`, `fail2ban-client status`, `firewall-cmd --state`).
   - Execute auditing tools (`lynis`, `rkhunter`, `chkrootkit`, `clamscan`).
   - Execute WP-CLI *strictly as the site's Linux owner* (`sudo -u <site-user> wp ...`), preventing root execution vulnerabilities.
   - Execute targeted active defense bans when configured (`fail2ban-client set <jail> banip/unbanip <ip>`).
3. **No Automatic Destructive Actions**: SHSM will never attempt to restart services, reload firewalls, or delete user files.

---

## 3. Installation via Git (Automated)

### Step 1: Install System Prerequisites
SHSM requires Python 3.9 or higher.

- **For Ubuntu 22.04 LTS or 24.04 LTS** (default repository provides Python 3.10+):
  ```bash
  sudo apt-get update
  sudo apt-get install -y git python3 python3-venv python3-pip
  ```

- **For Ubuntu 20.04 LTS** (default repository provides Python 3.8; install Python 3.11 via deadsnakes PPA):
  ```bash
  sudo apt-get update
  sudo apt-get install -y git software-properties-common
  sudo add-apt-repository -y ppa:deadsnakes/ppa
  sudo apt-get update
  sudo apt-get install -y python3.11 python3.11-venv python3.11-dev
  ```

### Step 2: Clone the Git Repository
Clone the official SHSM repository into `/opt/shsm-src`:
```bash
sudo git clone https://github.com/raw-dani/server-monitoring.git /opt/shsm-src
cd /opt/shsm-src
```

> [!NOTE]
> If `/opt/shsm-src` already exists from a previous installation or clone, navigate to the directory and pull the latest changes:
> ```bash
> cd /opt/shsm-src
> sudo git fetch origin
> sudo git checkout main
> sudo git pull
> ```

### Step 3: Run the Production Installer
Execute the installation script as root (or via `sudo`):
```bash
cd /opt/shsm-src
sudo bash scripts/install.sh
```

### What `install.sh` Does Automatically:
1. **Preflight Checks**: Verifies Ubuntu version, Python 3.9+ availability, and firewall binaries.
2. **Account Hardening Handling**: Temporarily unlocks `/etc/passwd` / `/etc/shadow` attributes (`chattr -ia`) if immutable flags were present, creates user `shsm:shsm`, adds required groups (`adm`, `proc`, `systemd-journal`), and restores original attributes.
3. **Directory Structure**:
   - `/opt/shsm`: Codebase and isolated Python virtual environment.
   - `/var/lib/shsm`: SQLite database (`monitoring.db`), backups, and PDF reports (`mode 0750 shsm:shsm`).
   - `/var/lib/shsm/locks`: Process lock directory (`mode 0750 shsm:shsm`).
   - `/var/log/shsm`: Rotating log directory (`mode 0750 shsm:shsm`).
   - `/etc/shsm`: Configuration files (`mode 0750 root:shsm`, files `mode 0640`).
   - `/etc/shsm/secrets`: Mode `0750 root:shsm` directory for secret files (`mode 0640 root:shsm`).
4. **CyberPanel MariaDB Auto-Configuration**: Detects `/etc/cyberpanel/mysqlPassword` and generates `/etc/shsm/secrets/my.cnf` with secure permissions (`0640 root:shsm`) so `shsm` can monitor database health without exposing passwords on CLI.
5. **Virtualenv**: Installs packages (`click`, `pyyaml`, `psutil`, `requests`, `reportlab`, `tzdata`).
6. **Symlink**: Links `/opt/shsm/venv/bin/shsm` to `/usr/local/bin/shsm`.
7. **Sudoers Rule**: Installs `/etc/sudoers.d/shsm` with syntax validation (`visudo -c`).
8. **Tmpfiles Configuration**: Installs `/etc/tmpfiles.d/shsm.conf` ensuring `/run/shsm` has proper `0775 shsm:shsm` permissions across server reboots.
9. **Database Migrations**: Applies all database tables in SQLite WAL mode.
10. **Systemd Timers**: Installs, throttles CPU/memory quotas, and activates all 21 timers (`Persistent=true`).
11. **Self-Test Verification**: Runs `shsm doctor` preflight validation.

---

## 4. Post-Installation Verification

Run the following commands to verify everything is operational:
```bash
# 1. Run diagnostic checks
sudo -u shsm shsm doctor

# 2. Collect initial metrics
sudo -u shsm shsm collect health
sudo -u shsm shsm collect services
sudo -u shsm shsm collect databases

# 3. Check overall server status
sudo -u shsm shsm status

# 4. Verify systemd timers are active
systemctl list-timers 'shsm-*'
```

---

## 5. Upgrading & Updating via Git

To update your production installation to the latest version released on GitHub without losing database history or configuration files:

```bash
# 1. Pull the latest commits from GitHub
cd /opt/shsm-src
sudo git pull

# 2. Run the automated upgrade script
# This creates an atomic DB backup, updates dependencies, runs new migrations, and refreshes systemd unit quotas
sudo bash scripts/upgrade.sh

# 3. Ensure sudoers rules are up to date
sudo cp scripts/shsm.sudoers /etc/sudoers.d/shsm
sudo chmod 0440 /etc/sudoers.d/shsm
sudo visudo -c

# 4. Verify status after upgrade
sudo -u shsm shsm doctor
sudo -u shsm shsm status
```
