# SHSM Configuration Guide

SHSM configuration is loaded from `/etc/shsm/config.yaml` (overridden by `$SHSM_CONFIG` environment variable or `--config <path>` flag).

---

## 1. Configuration Hierarchy & Precedence

1. **CLI Flag**: `--config /path/to/custom_config.yaml`
2. **Environment Variable**: `SHSM_CONFIG=/path/to/custom_config.yaml`
3. **Default Location**: `/etc/shsm/config.yaml`
4. **Environment Secret Overrides**: `SHSM_SMTP_PASSWORD`, `SHSM_REDIS_PASSWORD`, `SHSM_EXTERNAL_TOKEN`, etc.
5. **Built-in Safe Defaults**: Fallback when configuration keys are omitted.

To view your currently active merged configuration with all passwords and keys redacted:
```bash
sudo -u shsm shsm config show --redacted
```

---

## 2. Key Sections in `config.yaml`

### General
```yaml
general:
  server_name: "vps-production-01"  # Identifier used in email subjects, alerts & reports
  timezone: "Asia/Jakarta"          # IANA Timezone for local log and report timestamps
  log_level: "INFO"                 # DEBUG, INFO, WARNING, ERROR, CRITICAL
  read_only: true                   # Must remain true in v1 (read-only monitoring)
  data_retention_days: 365          # Retention period for metrics and reports
```

### Paths & Lock Directory
```yaml
paths:
  data_dir: "/var/lib/shsm"
  log_dir: "/var/log/shsm"
  config_dir: "/etc/shsm"
  report_dir: "/var/lib/shsm/reports"
  cache_dir: "/var/cache/shsm"
  rules_dir: "/etc/shsm/rules"
  lock_dir: "/var/lib/shsm/locks"    # Persistent lock directory owned by shsm:shsm
```

### Email & Notifications

SHSM supports flexible email delivery through any SMTP provider using presets or custom host configurations:

```yaml
email:
  enabled: true
  # Provider preset: custom | brevo | mailtrap | mailtrap_sandbox | sendgrid | mailgun | postmark | gmail | local
  provider: "brevo"
  smtp_host: "smtp-relay.brevo.com"   # Optional if provider is set; required if provider: "custom"
  smtp_port: 587                      # 587 (STARTTLS), 465 (SSL), 2525 (Mailtrap Sandbox), 25 (local)
  security: "starttls"                # starttls, ssl, none
  username: "your-account@domain.com" # Login username / 'apikey' for SendGrid
  password_file: "/etc/shsm/secrets/smtp_password" # Or SHSM_SMTP_PASSWORD env var
  from_name: "GM Teknologi Server Monitor"
  from_address: "alerts@yourdomain.com" # Sender address (required by SendGrid/Brevo/Mailtrap)
  recipients:
    - "rohmataliwardani@gmail.com"
  timeout_seconds: 20
  retries: 3
```

#### Provider Quick Setup Examples:

1. **Brevo (Sendinblue)**:
   ```yaml
   email:
     provider: "brevo"
     username: "your-brevo-login@domain.com"
     from_address: "alerts@yourdomain.com" # Must be a verified sender in Brevo
   ```
   *Store your Brevo SMTP Master Key (`xsmtpib-...`) in `/etc/shsm/secrets/smtp_password`.*

2. **Mailtrap (Production Email Sending)**:
   ```yaml
   email:
     provider: "mailtrap"
     username: "api"
     from_address: "alerts@your-verified-domain.com"
   ```
   *Store your Mailtrap API token in `/etc/shsm/secrets/smtp_password`.*

3. **Mailtrap (Testing Sandbox)**:
   ```yaml
   email:
     provider: "mailtrap_sandbox"
     username: "<your_mailtrap_sandbox_username>"
     from_address: "test@example.com"
   ```
   *Store your Mailtrap sandbox password in `/etc/shsm/secrets/smtp_password`.*

4. **SendGrid**:
   ```yaml
   email:
     provider: "sendgrid"
     username: "apikey"
     from_address: "alerts@your-verified-domain.com"
   ```
   *Store your SendGrid API Key (`SG.xxx`) in `/etc/shsm/secrets/smtp_password`.*

5. **Gmail**:
   ```yaml
   email:
     provider: "gmail"
     username: "your-email@gmail.com"
     from_address: "your-email@gmail.com"
   ```
   *Store your 16-character Google App Password in `/etc/shsm/secrets/smtp_password`.*

6. **Local Postfix / Exim (CyberPanel Local Mail)**:
   ```yaml
   email:
     provider: "local"
     from_address: "shsm@yourdomain.com"
   ```

7. **Mailgun**:
   ```yaml
   email:
     provider: "mailgun"
     username: "postmaster@your-domain.com"
     from_address: "alerts@your-domain.com"
   ```
   *Store your Mailgun SMTP password in `/etc/shsm/secrets/smtp_password`.*

8. **Amazon SES**:
   ```yaml
   email:
     provider: "ses"
     smtp_host: "email-smtp.us-east-1.amazonaws.com" # Sesuaikan region AWS Anda
     username: "AKIAIOSFODNN7EXAMPLE"                # SES SMTP Username
     from_address: "alerts@your-verified-domain.com"
   ```
   *Store your Amazon SES SMTP password in `/etc/shsm/secrets/smtp_password`.*

9. **Postmark**:
   ```yaml
   email:
     provider: "postmark"
     username: "your-postmark-server-api-token"
     from_address: "alerts@yourdomain.com"
   ```
   *Store your Postmark Server API Token in `/etc/shsm/secrets/smtp_password`.*

> [!NOTE]
> Setelah menyimpan password/API key ke file `/etc/shsm/secrets/smtp_password`, pastikan hak aksesnya aman:
> ```bash
> sudo chown root:shsm /etc/shsm/secrets/smtp_password
> sudo chmod 0640 /etc/shsm/secrets/smtp_password
> ```

### Alerting Rules & Thresholds
```yaml
alerts:
  enabled: true
  min_severity: "CRITICAL"          # INFO, LOW, MEDIUM, HIGH, CRITICAL
  min_confidence: "MEDIUM"          # LOW, MEDIUM, HIGH, CONFIRMED
  cooldown_minutes: 60              # Suppression window for duplicate alert emails
  recovery_notifications: true      # Send "RECOVERED" notification when issue is resolved
  max_items_per_email: 50

thresholds:
  cpu_warning: 80.0                 # Sustained % over 5-minute rolling window
  cpu_critical: 90.0
  cpu_emergency: 98.0
  load_per_cpu_warning: 1.5         # 5-minute load average divided by CPU count
  load_per_cpu_critical: 3.0
  load_per_cpu_emergency: 5.0
  memory_available_warning_percent: 15.0
  memory_available_critical_percent: 10.0
  memory_available_emergency_percent: 5.0
  disk_warning_percent: 80.0
  disk_critical_percent: 90.0
  disk_emergency_percent: 95.0
  ssl_warning_days: 30              # Days before certificate expiry
  ssl_high_days: 14
  ssl_critical_days: 7
  mail_queue_warning: 100           # Postfix queue size warning threshold
  mail_queue_critical: 500          # Postfix queue size critical threshold
  ddos_ip_conns_warning: 50         # Concurrent web connections from single IP
  ddos_ip_conns_critical: 150       # Concurrent web connections from single IP
  ddos_syn_warning: 100             # Half-open SYN_RECV sockets warning
  ddos_syn_critical: 300            # Half-open SYN_RECV sockets critical
```

### Services & Roles
```yaml
services:
  roles:
    openlitespeed:
      patterns: [lshttpd, lsws, openlitespeed]
      units: []
      required: true
    cyberpanel:
      patterns: [lscpd, cyberpanel]
      units: []
      required: false
    mariadb:
      patterns: [mariadb, mysql, mysqld]
      units: []
      required: true
    redis:
      patterns: [redis-server, redis]
      units: []
      required: false
    firewall:
      patterns: [ufw, firewalld, csf, lfd, nftables]
      units: []
      required: false
    cron:
      patterns: [cron, crond]
      units: []
      required: true
```

### Applications & Databases
```yaml
openlitespeed:
  enabled: "auto"                   # Discovers /usr/local/lsws automatically
  server_root: "/usr/local/lsws"
  config_file: "/usr/local/lsws/conf/httpd_config.conf"
  error_log: "/usr/local/lsws/logs/error.log"
  access_log: "/usr/local/lsws/logs/access.log"

mariadb:
  enabled: "auto"                   # Checks local socket automatically
  defaults_file: "/etc/shsm/secrets/my.cnf" # Auto-generated on CyberPanel or /etc/mysql/debian.cnf
  timeout_seconds: 15

redis:
  enabled: "auto"
  host: "127.0.0.1"
  port: 6379
  timeout_seconds: 5

wordpress:
  enabled: true
  wp_cli: "auto"                   # Discovers /usr/local/bin/wp (run as site owner)
```

### Security & Flexible Firewall Backends
SHSM supports multiple firewall technologies interchangeably:
```yaml
security:
  # Firewall backend options: auto | csf | firewalld | ufw | iptables | nftables | custom | none
  firewall_backend: "auto"

  # Anti-abuse & Botnet Scanner Auto-Blocking
  fail2ban_auto_block: true
  fail2ban_block_jail: "auto"       # 'auto' or specific jail name like 'ols-scanner'
  scanner_404_auto_block: true      # Automatically ban/drop IPs generating excessive 404 floods
  scanner_404_threshold: 50         # Max 404 errors per run from single IP before auto-drop

  # Whitelist of trusted IPs exempt from flood and scanner alerts (IMPORTANT: add your server public IP here!)
  ip_whitelist:
    - "127.0.0.1"
    - "::1"
    # - "206.183.128.56"             # Masukkan IP publik server Anda di sini agar tidak terblokir

  # Optional static public IP (if omitted, SHSM discovers it via external resolver)
  server_public_ip: ""

  # Anti-spam DNSBL / RBL providers to query for server IP reputation
  rbl_providers:
    - "zen.spamhaus.org"
    - "b.barracudacentral.org"
    - "bl.spamcop.net"
    - "dnsbl.sorbs.net"
    - "psbl.surriel.com"
    - "bl.mailspike.net"
```

Supported Backends:
- **`auto` (Default)**: Automatically detects whatever firewall is running (CSF, Firewalld, UFW, iptables, or nftables) through binary tools and systemd inspection.
- **`csf`**: ConfigServer Security & Firewall (standard on CyberPanel).
- **`firewalld`**: Dynamic firewall daemon (`firewall-cmd`).
- **`ufw`**: Uncomplicated Firewall (`ufw status`).
- **`iptables`**: Direct netfilter packet inspection (`iptables -L -n`).
- **`nftables`**: Modern Linux packet classification (`nft list ruleset`).
- **`custom`**: Runs an arbitrary status check array defined in `firewall_custom_cmd`.

### Periodic Reports & Formats (HTML & PDF)
SHSM secara berkala mengompilasi laporan eksekutif mingguan dan bulanan:
```yaml
paths:
  report_dir: "/var/lib/shsm/reports"  # Folder penyimpanan artefak report (weekly & monthly)
```

- **Output Format**:
  - **HTML (`.html`)**: Template HTML responsif mandiri (*self-contained inline CSS*) yang disematkan langsung sebagai *body* email.
  - **PDF (`.pdf`)**: Dokumen cetak multi-halaman berstandar profesional yang digenerate langsung oleh modul Python ReportLab, dan otomatis dilampirkan (*attachment*) pada email laporan.
- **Isi Laporan**:
  - Skor Kesehatan (*Health Score*) & Keamanan (*Security Score*) beserta cakupan persentasenya (*coverage %*).
  - Breakdown status per subsistem (*CPU, RAM, Disk, Database, Web & SSL, SSH, Firewall, WP Security*).
  - Ringkasan temuan terbuka (*Active Open Findings*) berprioritas tinggi.
  - Status ketersediaan website dan masa berlaku sertifikat SSL.

---

## 3. Secret Management & File Permissions

SHSM supports two secure methods for supplying secrets:
1. **Dedicated Secret Files (Recommended)**:
   - Secret directory: `/etc/shsm/secrets/` (mode `0750 root:shsm`).
   - Files: `/etc/shsm/secrets/my.cnf`, `/etc/shsm/secrets/smtp_password`, etc.
   - Permissions: `chmod 0640 /etc/shsm/secrets/*`, owned by `root:shsm` (or `chmod 0600 shsm:shsm`).
2. **Environment Variable Injection**:
   - `SHSM_SMTP_PASSWORD`
   - `SHSM_REDIS_PASSWORD`
   - `SHSM_EXTERNAL_TOKEN`
   - `SHSM_VULN_API_KEY`

---

## 4. Panduan Menerapkan Update ke Server Lain (Existing Server Upgrade)

Jika Anda memiliki server VPS lain yang sudah terinstal SHSM versi sebelumnya, ikuti langkah berikut untuk menerapkan seluruh fitur terbaru (**Anti-Spam Mail Queue, RBL Reputation, Anti-DDoS Sockets, dan Auto-Ban 404 Scanner**) tanpa merusak database dan histori monitoring:

### Langkah 1: Tarik Kode Terbaru & Jalankan Upgrade Script
Login via SSH ke server yang ingin di-upgrade:
```bash
cd /opt/shsm-src

# Tarik commit terbaru dari repositori Git Anda
git pull

# Jalankan script upgrade otomatis
# (Membuat backup DB otomatis, update virtualenv, sync unit systemd, dan reload daemon)
sudo bash scripts/upgrade.sh
```

### Langkah 2: Perbarui Izin Sudoers (Wajib untuk Fitur Auto-Drop iptables)
Pastikan user `shsm` memiliki izin untuk mengeksekusi perintah mitigasi iptables:
```bash
sudo cp scripts/shsm.sudoers /etc/sudoers.d/shsm
sudo chmod 0440 /etc/sudoers.d/shsm
sudo visudo -c
```

### Langkah 3: Perbarui File `/etc/shsm/config.yaml`
Tambahkan konfigurasi baru di `/etc/shsm/config.yaml` menggunakan editor teks (`sudo nano /etc/shsm/config.yaml`):

```yaml
thresholds:
  ...
  # [BARU] Ambang batas antrean mail & DDoS
  mail_queue_warning: 100
  mail_queue_critical: 500
  ddos_ip_conns_warning: 50
  ddos_ip_conns_critical: 150
  ddos_syn_warning: 100
  ddos_syn_critical: 300

security:
  ...
  # [BARU] Proteksi botnet scanner 404
  scanner_404_auto_block: true
  scanner_404_threshold: 50

  # [PENTING] Masukkan IP publik server tersebut agar tidak terkena blokir internal
  ip_whitelist:
    - "127.0.0.1"
    - "::1"
    - "<IP_PUBLIK_SERVER_ANDA>"
```

### Langkah 4: Aktifkan Timer Systemd Baru
Aktifkan 3 systemd timer yang baru ditambahkan:
```bash
sudo systemctl enable --now shsm-ddos.timer
sudo systemctl enable --now shsm-mail.timer
sudo systemctl enable --now shsm-security-rbl.timer
```

### Langkah 5: Terapkan Script Pengerasan Kernel DDoS (Layer-1 Drop)
Jalankan script pembantu untuk mengaktifkan TCP SYN cookies dan rate limiting:
```bash
sudo bash scripts/ddos_iptables_rules.sh
```

### Langkah 6: Verifikasi Hasil Upgrade
Pastikan seluruh subsistem berjalan dengan status hijau (*PASS*):
```bash
sudo -u shsm shsm doctor
sudo -u shsm shsm status
```

