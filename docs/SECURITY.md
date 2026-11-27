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

---

## 9. Anti-Spam & IP Blacklist Protection Hardening

Malware and webshells frequently attempt to turn VPS servers into outbound spam bots, which quickly gets the server public IP blacklisted across RBLs (Spamhaus, Barracuda, SpamCop).

### SHSM Detection Capabilities
1. **Mail Queue Audit (`shsm collect mail`)**:
   - Inspects Postfix spool directories or `mailq`. Alerts on queue spikes (> 100 warning, > 500 critical).
   - Automatically identifies top sender envelope addresses responsible for queue congestion.
2. **Outbound SMTP Socket Monitoring**:
   - Inspects TCP connections. Flags any non-MTA process (PHP-FPM, bash, perl, python, python3, unknown binaries) attempting direct connections to remote ports 25, 465, or 587.
3. **DNSBL / RBL Reputation Scan (`shsm security rbl`)**:
   - Periodically queries major anti-spam DNS blocklists (Spamhaus, Barracuda, SpamCop, SORBS, PSBL, Mailspike) to alert immediately if the IP gets blacklisted.

### Recommended OS / Firewall Hardening
To proactively prevent PHP scripts and malware from sending unauthorized outbound mail on port 25:

#### Block Outbound Port 25 Except for User `postfix` / `mail`
```bash
# Using iptables:
iptables -A OUTPUT -p tcp --dport 25 -m owner --uid-owner postfix -j ACCEPT
iptables -A OUTPUT -p tcp --dport 25 -m owner --uid-owner root -j ACCEPT
iptables -A OUTPUT -p tcp --dport 25 -d 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 25 -j REJECT --reject-with icmp-port-unreachable

# If using CSF (CyberPanel default):
# Ensure SMTP_BLOCK = "1" in /etc/csf/csf.conf
# This restricts outbound SMTP connections strictly to root, postfix, and mailman.
```

---

## 10. Anti-DDoS Early IP Blocking & Bot Challenge Hardening

To stop DDoS floods before they reach backend PHP and database workers:

### 1. SHSM Flood Detection
- **`shsm collect ddos`**:
  - Continuously samples kernel TCP sockets on ports 80/443 in < 25ms.
  - Detects SYN_RECV floods (SYN attacks) and single IPs opening > 50-150 concurrent connections.
- **`shsm security ols-ddos`**:
  - Audits OpenLiteSpeed tuning to verify that `perClientConnLimit` and `banPeriod` are properly enforced.

### 2. Kernel & Firewall Layer-1 Protection (`scripts/ddos_iptables_rules.sh`)
Execute the bundled hardening script:
```bash
sudo bash scripts/ddos_iptables_rules.sh
```
This enables TCP SYN cookies (`net.ipv4.tcp_syncookies = 1`) and rejects IP addresses attempting more than 80 concurrent connections directly at the Linux kernel packet filter (zero web server overhead).

### 3. OpenLiteSpeed Bot Challenge (Human vs Bot Verification)
In CyberPanel / OpenLiteSpeed WebAdmin Console:
1. Navigate to **Server Configuration -> Tuning -> Per Client Throttling**.
2. Set **Static/Dynamic Requests/sec** (e.g., 50-100).
3. Set **Banning Period (secs)** (e.g., 60-300).
4. Under **reCaptcha / Bot Verification**, enable the Anti-DDoS challenge. Legitimate web browsers will execute JavaScript and pass seamlessly, while headless bot scripts (curl, python, flooders) are instantly dropped with HTTP 403.

---

## 11. Scanner Bot Detection (404/403) & Instant IP Blocking

Aggressive web vulnerability scanners and botnets repeatedly probe random paths, exploit URIs, and endpoints, producing massive spikes of HTTP 404 (Not Found) or 403 (Forbidden) responses. These requests consume web server file handles and spawn unnecessary PHP workers.

### A. Instant Detection & Ban using SHSM (`block-scanners`)

SHSM provides a built-in automated scanner blocker that reads access logs, computes per-IP error counts, skips whitelist/internal IPs, and drops offending IPs at the Linux kernel packet filter layer (`iptables DROP`).

```bash
# 1. Preview / Dry-Run (Menampilkan status [SKIPPED] Already blocked vs [DRY-RUN] Would be blocked)
sudo -u shsm shsm block-scanners --threshold 10 --dry-run

# 2. Preview khusus IP yang BELUM diblokir saja
sudo -u shsm shsm block-scanners --threshold 10 --dry-run --unblocked-only

# 3. Execute Instant Ban (Drops all unblocked IPs exceeding threshold directly in firewall/ipset/iptables)
sudo -u shsm shsm block-scanners --threshold 10
```

> **Catatan:** Nilai `--threshold` menentukan batas minimal jumlah request error untuk memicu pemblokiran (misal `--threshold 10` atau `--threshold 30`).

### B. Real-Time Inspection via Shell / AWK

Untuk melihat daftar IP yang sedang aktif mengakses halaman 404 atau 403 beserta jumlah request-nya:

```bash
# Top 20 IP penghasil status 404 (Not Found)
awk '($9 ~ /404/) {print $1}' /usr/local/lsws/logs/access.log | sort | uniq -c | sort -rn | head -20

# Top 20 IP penghasil status 403 (Forbidden)
awk '($9 ~ /403/) {print $1}' /usr/local/lsws/logs/access.log | sort | uniq -c | sort -rn | head -20

# Gabungan Top 20 IP untuk 404 DAN 403 sekaligus
awk '($9 ~ /404|403/) {print $1}' /usr/local/lsws/logs/access.log | sort | uniq -c | sort -rn | head -20
```

### C. Manual & Batch Ban Operations

Jika ingin memblokir IP tertentu atau memblokir hasil ekstraksi log secara massal:

```bash
# 1. Blokir IP tunggal ke firewall kernel (0% CPU impact ke OLS/PHP)
sudo -u shsm shsm ban <IP> --iptables

# 2. Blokir massal semua IP dengan hit 404/403 >= 20 kali secara otomatis
awk '($9 ~ /404|403/) {print $1}' /usr/local/lsws/logs/access.log \
  | sort | uniq -c | sort -rn \
  | awk '$1 >= 20 {print $2}' \
  | while read ip; do
      sudo -u shsm shsm ban "$ip" --iptables
    done
```

### D. Audit & Unban

```bash
# Melihat seluruh daftar IP dan subnet yang saat ini diblokir
sudo -u shsm shsm blocked

# Memeriksa status blokir IP tertentu
sudo -u shsm shsm blocked <IP>

# Membuka blokir IP (menghapus dari Fail2Ban dan iptables sekaligus)
sudo -u shsm shsm unban <IP>
```


### 4. ConfigServer Security & Firewall (CSF / LFD)
Jika server menggunakan CSF/LFD (misal di lingkungan CyberPanel):
- **LFD (Login Failure Daemon)** menggantikan fungsi Fail2Ban untuk memitigasi brute-force SSH, FTP, dan webmail.
- **Port Khusus**: Pastikan port SSH kustom (misal 22891) selalu didaftarkan pada TCP_IN dan TCP_OUT di /etc/csf/csf.conf.
- **IP Whitelist**: IP administrator wajib didaftarkan di /etc/csf/csf.allow dan /etc/csf/csf.ignore agar tidak ter-block otomatis oleh LFD.
- **Daftar Blokir Manual / Script**: IP penyerang persisten dicatat di /etc/csf/csf.deny.
