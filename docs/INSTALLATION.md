# SHSM Installation Guide

This guide covers production deployment of **Server Health & Security Monitoring (SHSM)** on Ubuntu 20.04+ LTS VPS hosting CyberPanel, OpenLiteSpeed, MariaDB, and WordPress.

---

## 1. System Requirements

- **Operating System**: Ubuntu 20.04 LTS, 22.04 LTS, or 24.04 LTS.
- **Python**: Python 3.9, 3.10, 3.11, or 3.12 (with `python3-venv`).
- **Dependencies**: `systemd`, `sudo`, `sqlite3`.
- **Target Applications**:
  - CyberPanel (`/etc/cyberpanel/mysqlPassword`)
  - OpenLiteSpeed (`/usr/local/lsws/`)
  - MariaDB (`mariadb.service` / `/var/run/mysqld/mysqld.sock`)
  - Redis (`redis.service` / port 6379)
  - WP-CLI (`/usr/local/bin/wp`)

---

## 2. Security & Least Privilege Design

SHSM is designed from the ground up to follow the Principle of Least Privilege:
1. **Dedicated User**: Runs under system account `shsm` and group `shsm`.
2. **Sudoers Scope**: A strictly limited sudoers definition (`/etc/sudoers.d/shsm`) allows `shsm` to:
   - Run read-only diagnostics (`systemctl is-active`, `systemctl status`, `journalctl`, `ufw status`, `fail2ban-client status`).
   - Execute auditing tools (`lynis`, `rkhunter`, `chkrootkit`, `clamscan`).
   - Execute WP-CLI *strictly as the site's Linux owner* (`sudo -u <site-user> wp ...`), preventing root execution vulnerabilities.
3. **No Automatic Destructive Actions**: SHSM will never attempt to restart services, reload firewalls, or delete user files.

---

## 3. Automated Installation

Run the provided production installer:
```bash
sudo bash scripts/install.sh
```

### What `install.sh` Does:
1. **Preflight Checks**: Verifies Ubuntu version and Python 3.9+ availability.
2. **System Account**: Creates dedicated system user `shsm:shsm` (shell `/bin/false`).
3. **Directory Structure**:
   - `/opt/shsm`: Codebase and isolated virtual environment.
   - `/var/lib/shsm`: SQLite database (`monitoring.db`), backups, and PDF reports (`mode 0750`).
   - `/var/log/shsm`: Rotating log directory (`mode 0750`).
   - `/etc/shsm`: Configuration files (`mode 0750`, files `mode 0640`).
   - `/etc/shsm/secrets`: Mode `0700` directory for secret files (`0600`).
4. **Virtualenv**: Installs packages (`click`, `pyyaml`, `psutil`, `requests`, `reportlab`, `tzdata`).
5. **Symlink**: Links `/opt/shsm/venv/bin/shsm` to `/usr/local/bin/shsm`.
6. **Sudoers Rule**: Installs `/etc/sudoers.d/shsm` with syntax validation (`visudo -c`).
7. **Database Migrations**: Applies all 22 database tables in SQLite WAL mode.
8. **Systemd Timers**: Installs and activates all 21 timers (`Persistent=true`).

---

## 4. Manual / Step-by-Step Installation

If you prefer to configure manually:

### Step 1: System User
```bash
sudo groupadd --system shsm
sudo useradd --system --gid shsm --shell /bin/false --no-create-home shsm
sudo usermod -aG adm shsm
```

### Step 2: Virtual Environment
```bash
sudo mkdir -p /opt/shsm /var/lib/shsm /var/log/shsm /etc/shsm/secrets
sudo python3 -m venv /opt/shsm/venv
sudo cp -r src pyproject.toml /opt/shsm/
sudo /opt/shsm/venv/bin/pip install --upgrade pip setuptools wheel
sudo /opt/shsm/venv/bin/pip install -e /opt/shsm
sudo ln -sf /opt/shsm/venv/bin/shsm /usr/local/bin/shsm
```

### Step 3: Permissions
```bash
sudo chown -R shsm:shsm /opt/shsm /var/lib/shsm /var/log/shsm
sudo chown -R root:shsm /etc/shsm
sudo chmod 0750 /var/lib/shsm /var/log/shsm /etc/shsm
sudo chmod 0700 /etc/shsm/secrets
```

### Step 4: Sudoers Configuration
```bash
sudo cp scripts/shsm.sudoers /etc/sudoers.d/shsm
sudo chmod 0440 /etc/sudoers.d/shsm
sudo visudo -c -f /etc/sudoers.d/shsm
```

### Step 5: Initialize Database & Timers
```bash
sudo -u shsm shsm db migrate
sudo cp systemd/*.service systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
for t in /etc/systemd/system/shsm-*.timer; do
    sudo systemctl enable --now $(basename "$t")
done
```

---

## 5. Verification

Execute the self-test suite:
```bash
sudo bash scripts/self_test.sh
```
Or check timers:
```bash
systemctl list-timers 'shsm-*'
```
