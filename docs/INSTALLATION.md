# SHSM Installation Guide

This guide covers production deployment of **Server Health & Security Monitoring (SHSM)** on Ubuntu 20.04+ LTS VPS hosting CyberPanel, OpenLiteSpeed, MariaDB, Redis, and WordPress.

---

## 1. System Requirements

- **Operating System**: Ubuntu 20.04 LTS, 22.04 LTS, or 24.04 LTS.
- **Python**: Python 3.8, 3.9, 3.10, 3.11, or 3.12 (with `python3-venv`).
- **Dependencies**: `git`, `systemd`, `sudo`, `sqlite3`, `ipset` (recommended for O(1) kernel IP blocking).
- **Target Applications**:
  - CyberPanel (`/etc/cyberpanel/mysqlPassword`)
  - OpenLiteSpeed (`/usr/local/lsws/`)
  - MariaDB (`mariadb.service` / `/var/run/mysqld/mysqld.sock`)
  - Redis (`redis.service` / port 6379)
  - WP-CLI (`/usr/local/bin/wp`)
  - Firewall & Intrusion Prevention (auto-detected): **CSF/LFD**, **UFW**, **Firewalld**, **nftables**, **iptables**, and **Fail2Ban**.

---

## 2. Security & Least Privilege Architecture

SHSM is designed from the ground up to follow the Principle of Least Privilege:
1. **Dedicated User**: Runs under system account `shsm` and group `shsm` (with membership in `adm`, `nobody`, `nogroup`, `postfix`, `systemd-journal` as available).
2. **Sudoers Scope**: A strictly limited sudoers definition (`/etc/sudoers.d/shsm`) allows `shsm` to:
   - Run read-only diagnostics (`systemctl is-active`, `systemctl status`, `journalctl`, `postqueue -p`).
   - Execute auditing tools (`lynis`, `rkhunter`, `chkrootkit`, `clamscan`).
   - Execute WP-CLI *strictly as the site's Linux owner* (`sudo -u <site-user> wp ...`), preventing root execution vulnerabilities.
   - Inspect and apply targeted IP blocks against the active firewall backend (`csf -l/-td/-tr/-d/-dr`, `ufw status/insert/delete`, `firewall-cmd --state/--list-rich-rules/--add-rich-rule/--remove-rich-rule`, `nft list ruleset`, `ipset`, `iptables`/`ip6tables`, and `fail2ban-client`).
   - Execute emergency PHP worker reset (`killall -9 lsphp`) only when the emergency circuit-breaker threshold is sustained.
3. **Proxy & Loopback Safety**: Automatically protects loopback (`127.0.0.1`, `::1`), RFC1918 networks, server public/host IPs, and official Cloudflare IPv4/IPv6 edge ranges (`security.protect_cloudflare_ips: true`) from accidental local bans.

---

## 3. Installation on a New Server via Git

### Step 1: Install System Prerequisites
SHSM natively supports Python 3.8+ (including stock Python 3.8 in Ubuntu 20.04 LTS, and Python 3.10+ in Ubuntu 22.04 / 24.04). No third-party PPAs are required.

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip sqlite3 ipset
```

### Step 2: Clone the Git Repository
Clone the official SHSM repository into `/opt/shsm-src`:

```bash
sudo git clone https://github.com/raw-dani/server-monitoring.git /opt/shsm-src
cd /opt/shsm-src
```

> [!NOTE]
> If `/opt/shsm-src` already exists from a previous installation or clone, pull the latest changes:
> ```bash
> cd /opt/shsm-src
> sudo git fetch origin
> sudo git checkout main
> sudo git pull origin main
> ```

### Step 3: Run the Production Installer
Execute the installation script as root (or via `sudo`):

```bash
cd /opt/shsm-src
sudo bash scripts/install.sh
```

### Step 4: (Recommended) Apply Tier-1 Kernel Anti-DDoS Hardening
Applies `sysctl` SYN flood protections, `INVALID` packet drops, per-IP `hashlimit` rate limiting, `connlimit` (max 80 simultaneous connections/IP on ports 80/443), and O(1) `ipset` blacklist hooks (`shsm_blacklist` / `shsm_blacklist_v6`):

```bash
cd /opt/shsm-src
sudo bash scripts/ddos_iptables_rules.sh
```

### What `install.sh` Does Automatically:
1. **Preflight Checks**: Verifies Ubuntu version, Python 3.8+ availability, `ipset`, optional scanners (`fail2ban-client`, `wp`, `lynis`, `rkhunter`, `clamscan`), and firewall binaries (`csf`, `firewall-cmd`, `ufw`, `iptables`, `nft`).
2. **Account Hardening Handling**: Temporarily unlocks `/etc/passwd` / `/etc/shadow` attributes (`chattr -ia`) if immutable flags were present, creates user `shsm:shsm`, adds required groups (`adm`, `proc`, `systemd-journal`, `nobody`, `nogroup`, `postfix`), and restores original attributes.
3. **Directory Structure**:
   - `/opt/shsm`: Codebase and isolated Python virtual environment.
   - `/var/lib/shsm`: SQLite database (`monitoring.db`), backups, and HTML/PDF reports (`mode 0750 shsm:shsm`).
   - `/var/lib/shsm/locks`: Process lock directory (`mode 0750 shsm:shsm`).
   - `/var/log/shsm`: Rotating log directory (`mode 0750 shsm:shsm`).
   - `/etc/shsm`: Configuration files (`mode 0750 root:shsm`, files `mode 0640`).
   - `/etc/shsm/secrets`: Mode `0750 root:shsm` directory for secret files (`mode 0640 root:shsm`).
4. **CyberPanel MariaDB Auto-Configuration**: Detects `/etc/cyberpanel/mysqlPassword` (or `/root/.my.cnf`) and generates `/etc/shsm/secrets/my.cnf` (`0640 root:shsm`) so `shsm` can monitor MariaDB health securely.
5. **Virtualenv & Symlink**: Installs dependencies and links `/opt/shsm/venv/bin/shsm` to `/usr/local/bin/shsm`.
6. **Sudoers & Tmpfiles**: Installs `/etc/sudoers.d/shsm` (`visudo -c` validated) and `/etc/tmpfiles.d/shsm.conf` for `/run/shsm`.
7. **Database Migrations**: Applies all SQLite WAL schema migrations.
8. **Systemd Timers & Real-Time Watcher**: Installs and starts all scheduled `shsm-*.timer` units **and** the lightweight `shsm-watch.service` real-time adaptive anti-DDoS & L7 flood watcher daemon (`MemoryMax=128M`, `CPUQuota=15%`).
9. **Self-Test Verification**: Runs `sudo -u shsm shsm doctor`.

---

## 4. Post-Installation Configuration & Initial Discovery

### Step 1: Configure Email, Server IP & Security Options
Edit `/etc/shsm/config.yaml` (and ensure secret files inside `/etc/shsm/secrets/` are owned `root:shsm` mode `0640`):

```bash
sudo nano /etc/shsm/config.yaml
```

Key settings to review on a new server:
- `email.*`: SMTP host, port, `username`, `password_file` (`/etc/shsm/secrets/smtp_password`), `recipients`, `daily_recipients`, `weekly_recipients`, `monthly_recipients`.
- `security.firewall_backend`: Leave as `auto` (auto-detects CSF, UFW, Firewalld, nftables, or iptables) unless you want to pin a specific backend.
- `security.server_public_ip`: Set your VPS public IPv4 so SHSM always keeps it whitelisted.
- `security.cloudflare_enabled`: Set `true` (with `cloudflare_zone_id` and `/etc/shsm/secrets/cloudflare_token`) if domains are proxied behind Cloudflare and you want automatic WAF Access Rule blocking.

Validate configuration syntax:
```bash
sudo -u shsm shsm config validate
```

### Step 2: Run Initial Discovery, Baseline & Verification
Run these once after installation so reports and inventory are populated immediately:

```bash
# 1. Verify environment, active firewall backend, and permissions
sudo -u shsm shsm doctor

# 2. Discover websites & WordPress sites, and clean up any dead/parked domains
sudo -u shsm shsm websites discover
sudo -u shsm shsm websites cleanup
sudo -u shsm shsm wordpress discover

# 3. Initialize File Integrity Monitoring (FIM) baseline
sudo shsm integrity baseline --update

# 4. Run initial health, services, database, and website checks
sudo -u shsm shsm collect health
sudo -u shsm shsm collect services
sudo -u shsm shsm collect databases
sudo -u shsm shsm websites check

# 5. Test real-time anti-DDoS watcher & preview first report
sudo -u shsm shsm watch --once --dry-run
sudo -u shsm shsm report daily --preview

# 6. Check status, active timers, and watch daemon
sudo -u shsm shsm status
systemctl status shsm-watch.service --no-pager
systemctl list-timers 'shsm-*'
```

---

## 5. Upgrading & Updating via Git

To update your production installation to the latest version released on GitHub without losing database history or configuration files:

```bash
# 1. Pull the latest commits from GitHub
cd /opt/shsm-src
sudo git pull origin main

# 2. Run the automated upgrade script
# This creates an atomic DB backup in /var/lib/shsm/backups, syncs new files, updates dependencies,
# enforces non-root shsm:shsm ownership, updates sudoers, applies migrations, and refreshes systemd timers + shsm-watch.service
sudo bash scripts/upgrade.sh

# 3. Ensure CLI symlink is active
sudo ln -sf /opt/shsm/venv/bin/shsm /usr/local/bin/shsm

# 4. Verify system health, active firewall, and timers after upgrade
sudo -u shsm shsm doctor
sudo -u shsm shsm status
systemctl status shsm-watch.service --no-pager
systemctl list-timers 'shsm-*'
```

> **Note:**
> - Your existing configuration in `/etc/shsm/config.yaml` and monitoring history in `/var/lib/shsm/monitoring.db` are completely preserved during upgrades.
> - Always execute CLI commands using `sudo -u shsm shsm <command>` (except `integrity baseline` / `install.sh` / `upgrade.sh` which require root) to maintain SQLite database permission integrity.
