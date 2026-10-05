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
  - Firewall: CSF, Firewalld, UFW, or iptables

---

## 2. Security & Least Privilege Architecture

SHSM is designed from the ground up to follow the Principle of Least Privilege:
1. **Dedicated User**: Runs under system account `shsm` and group `shsm`.
2. **Sudoers Scope**: A strictly limited sudoers definition (`/etc/sudoers.d/shsm`) allows `shsm` to:
   - Run read-only diagnostics (`systemctl is-active`, `systemctl status`, `journalctl`, `ufw status`, `fail2ban-client status`, `firewall-cmd --state`).
   - Execute auditing tools (`lynis`, `rkhunter`, `chkrootkit`, `clamscan`).
   - Execute WP-CLI *strictly as the site's Linux owner* (`sudo -u <site-user> wp ...`), preventing root execution vulnerabilities.
3. **No Automatic Destructive Actions**: SHSM will never attempt to restart services, reload firewalls, or delete user files.

---

## 3. Automated Installation

Run the provided production installer as root:
```bash
cd /opt/shsm-src
sudo bash scripts/install.sh
```

### What `install.sh` Does Automatically:
1. **Preflight Checks**: Verifies Ubuntu version, Python 3.9+ availability, and firewall binaries.
2. **Account Hardening Handling**: Temporarily unlocks `/etc/passwd` / `/etc/shadow` attributes (`chattr -ia`) if immutable flags were present, creates user `shsm:shsm`, and restores original attributes.
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
9. **Database Migrations**: Applies all 22 database tables in SQLite WAL mode.
10. **Systemd Timers**: Installs and activates all 21 timers (`Persistent=true`).
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
