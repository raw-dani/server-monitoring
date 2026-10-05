# SHSM Security Policy & Architecture

Security is the primary guiding principle of the SHSM architecture. This document outlines the guarantees, constraints, and threat mitigation mechanisms built into SHSM.

---

## 1. Strict Read-Only Philosophy

- **Zero Automatic Remediation**: SHSM will **never** automatically execute `systemctl restart`, `kill`, `rm`, `chmod`, `ufw reload`, or database modifications.
- **Accidental Disruption Prevention**: In production, automated "self-healing" often causes cascading outages (e.g. repeatedly restarting a flapping service that has corrupted configuration). SHSM leaves corrective actions to the human administrator while providing detailed diagnosis and evidence.

---

## 2. Least-Privilege & Non-Root Execution

### The Dedicated `shsm` User
SHSM executes under a dedicated system user `shsm:shsm`. It has no interactive login shell (`/bin/false`) and no home directory.

### Sudoers Restrictions (`/etc/sudoers.d/shsm`)
The `shsm` user is granted limited sudo privileges strictly for:
- Reading system service states (`systemctl is-active`, `systemctl status`, `systemctl show`, `systemctl list-units`).
- Reading systemd journal logs (`journalctl`).
- Querying firewall status (`ufw status`, `firewall-cmd --state`, `iptables -L`).
- Querying Fail2Ban status (`fail2ban-client status`).
- Running read-only security scanners (`lynis`, `rkhunter`, `clamscan`).
- Executing WP-CLI *strictly as the site's Linux owner* (`sudo -u <site-user> wp ...`).

### WordPress WP-CLI Safety (Never Root)
Executing WP-CLI as `root` can corrupt file ownership (e.g., creating cache files owned by root inside `/home/user/public_html/`) or trigger malicious code execution with root privileges.
- SHSM discovers the Linux UID/username of each WordPress site's document root (e.g., `wpuser1`).
- SHSM invokes WP-CLI strictly through:
  ```bash
  sudo -u wpuser1 /usr/local/bin/wp --path=/home/example.com/public_html <command>
  ```
- Root execution of WP-CLI is explicitly blocked in code.

---

## 3. Mandatory Secret Redaction

SHSM enforces redaction at four distinct pipeline boundaries:
1. **Subprocess Execution**: Standard output and error streams are redacted before parsing or storage.
2. **Database Persistence**: Any evidence strings containing tokens, passwords, hashes, or API keys are masked prior to SQLite inserts.
3. **CLI & Logging**: All console outputs, error traces, and `/var/log/shsm/shsm.log` messages pass through `RedactingFilter`.
4. **Email & PDF Reports**: IP addresses are masked to subnet blocks (`192.168.1.0/24`), email addresses are masked (`r***@domain.com`), and credentials are replaced with `[REDACTED]`.

---

## 4. Secret Storage & File Permissions

Secret files containing database passwords, API tokens, or SMTP passwords:
- Stored in `/etc/shsm/secrets/`.
- Must have secure file modes: `0640 root:shsm` (readable only by root and members of the `shsm` group) or `0600`.
- World-readable or group-writable permissions are strictly rejected during preflight validation (`shsm doctor`).

---

## 5. Subprocess Isolation & Safety

All external commands executed by SHSM adhere to strict rules:
- **No `shell=True`**: All commands use argument lists (`Sequence[str]`) avoiding shell injection.
- **Mandatory Timeouts**: Every subprocess call has a hard timeout (10s to 300s) preventing hung processes.
- **Bounded Output**: Output captures are capped at 2MB to prevent memory exhaustion from runaway log dumps.
- **Sanitized Environment**: Shell environment variables are restricted to safe keys (`PATH`, `LANG`, `LC_ALL`, `TZ`).

---

## 6. File Integrity Monitoring (FIM)

SHSM tracks cryptographic SHA-256 hashes, file sizes, permissions, and modification times for critical configuration files:
- `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/`
- `/etc/ssh/sshd_config`, `/etc/crontab`, `/etc/cron.d/`
- `/etc/systemd/system/`
- `/etc/hosts`, `/etc/fstab`

Deltas trigger high-confidence security findings with previous and new attribute diffs.

### Baseline Maintenance
When legitimate administrative changes are made to server configuration:
```bash
sudo -u shsm shsm integrity baseline --update
```
