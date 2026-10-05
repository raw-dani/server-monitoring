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
```yaml
email:
  enabled: true
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  security: "starttls"              # starttls, ssl, none
  username: "monitoring@example.com"
  password_file: "/etc/shsm/secrets/smtp_password" # Or SHSM_SMTP_PASSWORD env var
  from_name: "GM Teknologi Server Monitor"
  from_address: "monitoring@example.com"
  recipients:
    - "rohmataliwardani@gmail.com"
  timeout_seconds: 20
  retries: 3
```

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

  # Optional custom command (only if firewall_backend: "custom")
  # firewall_custom_cmd: ["/usr/sbin/iptables", "-L", "-n"]
```

Supported Backends:
- **`auto` (Default)**: Automatically detects whatever firewall is running (CSF, Firewalld, UFW, iptables, or nftables) through binary tools and systemd inspection.
- **`csf`**: ConfigServer Security & Firewall (standard on CyberPanel).
- **`firewalld`**: Dynamic firewall daemon (`firewall-cmd`).
- **`ufw`**: Uncomplicated Firewall (`ufw status`).
- **`iptables`**: Direct netfilter packet inspection (`iptables -L -n`).
- **`nftables`**: Modern Linux packet classification (`nft list ruleset`).
- **`custom`**: Runs an arbitrary status check array defined in `firewall_custom_cmd`.
- **`none`**: Disables firewall presence checks if the VPS uses an external cloud provider security group (e.g. AWS Security Group / DigitalOcean Cloud Firewall).

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
