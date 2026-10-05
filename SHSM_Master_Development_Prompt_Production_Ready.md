# MASTER DEVELOPMENT PROMPT

# Server Health & Security Monitoring (SHSM)

## Production-Ready CLI Monitoring System for Ubuntu + CyberPanel + OpenLiteSpeed + WordPress

**Project:** Server Health & Security Monitoring (SHSM)\
**Owner:** GM Teknologi\
**Default report recipient:** rohmataliwardani@gmail.com\
**Timezone:** Asia/Jakarta\
**Deployment:** Single Ubuntu server\
**Interface:** CLI only\
**Status:** Full implementation brief for a coding agent

------------------------------------------------------------------------

# 1. ROLE AND MISSION

You are a senior Python software architect, Linux systems engineer,
DevSecOps engineer, application security engineer, and QA engineer.

Your task is to design, implement, test, document, and package a
complete production-ready application named **Server Health & Security
Monitoring (SHSM)**.

SHSM runs locally on an Ubuntu server hosting:

-   CyberPanel
-   OpenLiteSpeed
-   Multiple websites and WordPress installations
-   MariaDB
-   Redis
-   PHP
-   SSH
-   Firewall and Fail2Ban, where installed

The application must monitor server health, hosting services, website
availability, WordPress security, host security, suspicious files, and
system integrity. It must store monitoring data locally, send immediate
critical alerts, and automatically email weekly and monthly reports.

This is a real production software project. Do not stop at architecture
diagrams, pseudocode, placeholder functions, empty modules, or a basic
proof of concept. Implement working code and tests for every feature in
scope.

If the repository already contains user work, inspect it first and
preserve it. Never overwrite unrelated files.

# 2. APPROVED PRODUCT DECISIONS --- DO NOT CHANGE

  -----------------------------------------------------------------------
  Area                                Approved decision
  ----------------------------------- -----------------------------------
  Application name                    Server Health & Security Monitoring
                                      (SHSM)

  Interface                           CLI only

  Dashboard                           Not included in v1

  Programming language                Python 3

  Database                            SQLite

  Scheduling                          systemd services and timers

  Target OS                           Ubuntu 20.04+ subject to
                                      dependency/security support

  Hosting panel                       CyberPanel

  Webserver                           OpenLiteSpeed

  Database service                    MariaDB

  Cache                               Redis

  Website engine                      Multiple WordPress installations

  Malware scanning                    Custom heuristic + ClamAV + Lynis +
                                      rkhunter and/or chkrootkit

  WordPress integration               WP-CLI, executed as the website
                                      owner

  External monitoring                 Yes; independent heartbeat and
                                      external website/SSL checks

  Architecture                        Single monitored server

  Report formats                      HTML email and PDF attachment

  Email transport                     Configurable SMTP, STARTTLS or
                                      implicit TLS

  Default recipient                   rohmataliwardani@gmail.com

  Timezone                            Asia/Jakarta

  Default security mode               Read-only

  Automated remediation               Disabled; not included in v1
  -----------------------------------------------------------------------

Do not introduce a web dashboard, public HTTP server, agent fleet,
central multi-server control plane, or automatic remediation unless
explicitly requested in a later project phase.

# 3. PRIMARY OBJECTIVES

The completed application must:

1.  Collect CPU, RAM, swap, disk, inode, load, I/O, and network metrics.
2.  Monitor critical system and hosting services.
3.  Monitor OpenLiteSpeed service state, logs, virtual-host errors, and
    HTTP failures.
4.  Monitor MariaDB and Redis using lightweight read-only checks.
5.  Discover CyberPanel websites and WordPress installations
    automatically.
6.  Audit WordPress core, plugins, themes, administrator accounts,
    checksums, and suspicious files.
7.  Detect suspicious files, malware indicators, rootkit indicators, and
    unauthorized system/file changes.
8.  Audit SSH, authentication events, firewall, listening ports, and
    Fail2Ban.
9.  Monitor website HTTP/HTTPS availability, DNS resolution, response
    time, and SSL expiry.
10. Maintain findings, severity, confidence, history, and remediation
    guidance.
11. Generate independent Server Health and Security scores with coverage
    indicators.
12. Send immediate deduplicated critical alerts by email.
13. Send weekly and monthly HTML/PDF reports automatically.
14. Send heartbeat data to an external monitoring provider.
15. Provide safe install, upgrade, uninstall, backup, restore,
    self-test, and diagnostics.
16. Run with low resource consumption and without disrupting hosted
    websites.

# 4. NON-NEGOTIABLE ENGINEERING AND SAFETY RULES

## 4.1 Read-only by default

SHSM must not automatically:

-   Delete website files.
-   Quarantine or modify files.
-   Change file permissions or ownership.
-   Modify SSH configuration.
-   Change firewall rules.
-   Block IP addresses.
-   Restart or stop hosting services.
-   Change OpenLiteSpeed configuration.
-   Modify MariaDB or Redis configuration.
-   Update WordPress core, plugins, or themes.
-   Create, disable, or delete WordPress users.
-   Change CyberPanel settings.

The application may generate recommendations and provide evidence for an
administrator to act upon.

## 4.2 Safe command execution

-   Use `subprocess.run()` with argument arrays, not shell string
    concatenation.
-   Apply timeouts to every external command.
-   Validate all command arguments and paths.
-   Do not use untrusted log values as command arguments.
-   Never execute scanned files.
-   Avoid `shell=True`.
-   Capture bounded output and redact secrets.
-   Handle command not found, timeout, permission denied, and non-zero
    exit codes explicitly.

## 4.3 Least privilege

-   Use a dedicated service account for unprivileged collection wherever
    practical.
-   Use narrowly scoped privileged helpers or sudo rules for checks that
    genuinely require root.
-   Do not grant unrestricted sudo to the application service account.
-   Execute WP-CLI as the Linux owner of each WordPress installation.
-   Use a least-privilege MariaDB monitoring account.
-   Respect Redis authentication and TLS configuration.
-   Protect all configuration, secrets, databases, logs, reports, and
    baselines.

## 4.4 Unknown is not healthy

Every check must return a structured result such as:

-   PASS
-   WARNING
-   CRITICAL
-   UNKNOWN
-   ERROR
-   NOT_APPLICABLE

If a tool is missing, access is denied, a scan is incomplete, or a data
source is unavailable, do not report the check as passing.

Reports must display coverage, last successful scan time, unavailable
checks, and scan errors.

## 4.5 Data confidentiality

Never disclose in CLI output, logs, database records, emails, or
reports:

-   SMTP passwords.
-   API tokens.
-   Redis passwords.
-   Database passwords.
-   WordPress salts.
-   WordPress database credentials.
-   Private SSH keys.
-   Password hashes.
-   Cookies or session tokens.
-   Full sensitive configuration files.
-   Full raw authentication log lines.
-   Full source code of suspicious files.

# 5. REQUIRED TECHNOLOGY AND PROJECT QUALITY

Use:

-   Python 3.
-   A virtual environment.
-   A CLI framework such as Typer or Click.
-   SQLite with migrations.
-   SQL parameterization.
-   `psutil` or equivalent for system metrics.
-   `PyYAML` or equivalent for configuration.
-   `requests` or an equivalent maintained HTTP client.
-   A maintained PDF generation library.
-   Standard Python logging with redaction.
-   pytest for tests.
-   Ruff or equivalent linting.
-   Type checking where practical.

Pin dependencies and generate a reproducible lock file. Avoid
unnecessary packages. Document supported Python and Ubuntu versions.

# 6. APPLICATION ARCHITECTURE

Implement the following layers:

1.  CLI and command routing.
2.  Configuration and validation.
3.  Core execution runner.
4.  Safe subprocess and privilege helper.
5.  Collectors.
6.  Discovery engine.
7.  Security scanners.
8.  Findings and correlation engine.
9.  SQLite repositories and migrations.
10. Scoring engine.
11. Alert manager.
12. SMTP notification adapter.
13. External heartbeat adapter.
14. Report generation.
15. Retention and backup.
16. systemd deployment assets.

Use clear interfaces so each collector/scanner can be tested
independently.

Use short-lived CLI jobs scheduled by systemd timers. Do not run an
unnecessary permanent Python scheduler.

# 7. REQUIRED PROJECT STRUCTURE

Create a clean structure similar to:

``` text
/opt/shsm/
├── pyproject.toml
├── requirements.lock
├── README.md
├── CHANGELOG.md
├── LICENSE
├── src/
│   └── shsm/
│       ├── __init__.py
│       ├── cli.py
│       ├── config.py
│       ├── logging_config.py
│       ├── core/
│       │   ├── runner.py
│       │   ├── locks.py
│       │   ├── findings.py
│       │   ├── subprocesses.py
│       │   ├── retention.py
│       │   └── timeutils.py
│       ├── database/
│       │   ├── connection.py
│       │   ├── migrations/
│       │   └── repositories/
│       ├── discovery/
│       │   ├── cyberpanel.py
│       │   ├── wordpress.py
│       │   ├── services.py
│       │   └── paths.py
│       ├── collectors/
│       │   ├── cpu.py
│       │   ├── memory.py
│       │   ├── disk.py
│       │   ├── process.py
│       │   ├── services.py
│       │   ├── network.py
│       │   ├── openlitespeed.py
│       │   ├── mariadb.py
│       │   ├── redis.py
│       │   ├── websites.py
│       │   └── ssl.py
│       ├── security/
│       │   ├── ssh.py
│       │   ├── firewall.py
│       │   ├── fail2ban.py
│       │   ├── malware.py
│       │   ├── clamav.py
│       │   ├── lynis.py
│       │   ├── rootkit.py
│       │   ├── wordpress.py
│       │   ├── integrity.py
│       │   └── vulnerability.py
│       ├── reporting/
│       │   ├── scoring.py
│       │   ├── weekly.py
│       │   ├── monthly.py
│       │   ├── html.py
│       │   └── pdf.py
│       ├── notifications/
│       │   ├── smtp.py
│       │   ├── alerts.py
│       │   └── external.py
│       └── utils/
├── config/
│   ├── config.example.yaml
│   ├── thresholds.example.yaml
│   └── paths.example.yaml
├── templates/
│   ├── email/
│   └── reports/
├── scripts/
│   ├── install.sh
│   ├── upgrade.sh
│   ├── uninstall.sh
│   └── self_test.sh
├── systemd/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
└── docs/
    ├── INSTALLATION.md
    ├── CONFIGURATION.md
    ├── SECURITY.md
    ├── OPERATIONS.md
    ├── BACKUP_RESTORE.md
    ├── TROUBLESHOOTING.md
    └── EXTERNAL_MONITORING.md
```

Runtime directories must be separate:

``` text
/etc/shsm/
  config.yaml
  secrets/
  rules/

/var/lib/shsm/
  monitoring.db
  baseline/
  state/
  reports/
    weekly/
    monthly/

/var/log/shsm/
/var/cache/shsm/
```

Application code should be owned by root. Secret files must be
root-owned and mode `0600`. Baseline directories must be root-only.
Choose service ownership and group access deliberately; do not make all
data world-readable.

# 8. CONFIGURATION SYSTEM

Implement validated YAML configuration with safe defaults.

Example:

``` yaml
general:
  server_name: auto
  timezone: Asia/Jakarta
  log_level: INFO
  read_only: true
  data_retention_days: 365

paths:
  data_dir: /var/lib/shsm
  log_dir: /var/log/shsm
  config_dir: /etc/shsm
  report_dir: /var/lib/shsm/reports

email:
  enabled: true
  smtp_host: smtp.gmail.com
  smtp_port: 587
  security: starttls
  username: ""
  password_file: /etc/shsm/secrets/smtp_password
  from_name: GM Teknologi Server Monitor
  from_address: ""
  recipients:
    - rohmataliwardani@gmail.com
  timeout_seconds: 20
  retries: 3

schedule:
  timezone: Asia/Jakarta
  weekly_day: monday
  weekly_time: "07:00"
  monthly_day: 1
  monthly_time: "07:00"

external_monitoring:
  enabled: false
  provider: generic_webhook
  heartbeat_url: ""
  token_file: /etc/shsm/secrets/external_token
  interval_seconds: 300
  timeout_seconds: 15

monitoring:
  metrics_interval_seconds: 60
  service_interval_seconds: 60
  database_interval_seconds: 300
  website_interval_seconds: 300
  ssl_interval_seconds: 21600
  wordpress_discovery_interval_seconds: 21600

scanning:
  quick_scan_daily: true
  full_scan_weekly: true
  full_scan_window: "02:00-05:00"
  max_workers: 2
  max_file_size_mb: 50
  max_depth: 20
  follow_symlinks: false

thresholds:
  cpu_warning: 80
  cpu_critical: 90
  cpu_emergency: 95
  memory_available_warning_percent: 20
  memory_available_critical_percent: 10
  memory_available_emergency_percent: 5
  disk_warning_percent: 80
  disk_critical_percent: 90
  disk_emergency_percent: 95
  inode_warning_percent: 80
  inode_critical_percent: 90
  inode_emergency_percent: 95
  ssl_warning_days: 30
  ssl_high_days: 14
  ssl_critical_days: 7
```

The configuration system must: - Validate types and ranges. - Reject
unknown critical settings or warn clearly. - Support environment
variable overrides for secrets. - Never print secret values. - Provide
`shsm config validate`. - Provide `shsm config show --redacted`. -
Create a secure initial configuration during installation. - Never
overwrite an existing configuration without backup and explicit
approval.

# 9. MODULE 1 --- SERVER HEALTH MONITORING

Implement collectors for:

## CPU

-   Overall and per-core utilization.
-   Load averages 1/5/15.
-   CPU steal.
-   CPU iowait.
-   Top CPU processes.
-   Sustained threshold detection.

## Memory and swap

-   Total, used, available, cache, buffers.
-   Swap total and used.
-   Swap activity where available.
-   Top memory processes.
-   OOM events.

Use `MemAvailable` where supported. Do not treat Linux cache as fully
consumed application memory.

## Disk and inode

-   Every relevant mounted filesystem.
-   Used/free capacity.
-   Inode use.
-   Disk growth.
-   Disk I/O indicators.
-   Largest configured directories using bounded scans.
-   Log growth anomalies.

Do not recursively size the entire filesystem at high frequency.

## Network

-   Interface RX/TX counters.
-   Error and dropped packet counters.
-   TCP connection summaries.
-   Listening ports.
-   Unusual outbound connections where reliable process attribution is
    available.

## Process

-   CPU/RAM-heavy processes.
-   Zombie processes.
-   Unexpected privileged executables.
-   Process restart anomalies where detectable.

## Default thresholds

  Metric              Warning    Critical   Emergency
  --------------- ----------- ----------- -----------
  Sustained CPU           80%         90%         95%
  RAM available     below 20%   below 10%    below 5%
  Disk usage              80%         90%         95%
  Inodes                  80%         90%         95%
  Swap used               50%         75%         90%

CPU alerts must use rolling duration rather than one sample. Evaluate
load relative to CPU count. CPU steal and iowait must be separate
findings.

# 10. MODULE 2 --- SERVICE MONITORING

Discover and monitor installed services, including:

-   OpenLiteSpeed.
-   CyberPanel-related services.
-   MariaDB.
-   Redis.
-   SSH.
-   Fail2Ban.
-   Active firewall service.
-   Cron and SHSM systemd units.

Do not hard-code service names without discovery and configuration
overrides.

Record service status, process ID, uptime, recent restarts, and failure
reason where available.

Detect: - Service unexpectedly stopped. - Repeated restarts. - Failed
systemd units. - New systemd unit files in sensitive directories. -
Unusual privileged processes.

Do not automatically restart services.

# 11. MODULE 3 --- OPENLITESPEED MONITORING

Discover actual OpenLiteSpeed binary, service, configuration, and log
paths.

Monitor: - Service state. - Process count and resource use. - Access log
request counts. - HTTP 5xx and 4xx rates. - PHP fatal errors. - PHP
memory exhaustion. - Timeout and upstream errors. - SSL handshake
errors. - Virtual-host-level error concentrations. - Abnormal restart
events.

Implement incremental log parsing: - Persist file identity, inode, and
byte offset. - Handle rotation, truncation, and inode changes. - Avoid
rereading old logs. - Handle malformed lines safely. - Treat log values
as untrusted. - Escape log excerpts in reports. - Apply bounded
processing per run.

Provide configurable log paths and parsing fixtures for tests.

# 12. MODULE 4 --- MARIADB MONITORING

Use a dedicated least-privilege account or safe local socket
authentication.

Collect: - Service state. - Uptime. - Connection count and max
connections. - Aborted connections. - Slow query counters and slow log
configuration. - InnoDB buffer pool indicators. - Deadlock indicators
where available. - Database size estimates. - Error log summary.

Use lightweight queries. Do not frequently execute expensive
process-list or full-table queries. Do not collect query text by
default.

Credentials must not be placed in command-line arguments or logs.

# 13. MODULE 5 --- REDIS MONITORING

Collect: - PING and latency. - Memory used and max memory. - Connected
clients. - Hit/miss statistics. - Evicted and expired keys. -
Persistence state. - Uptime. - Connection failures.

Respect password and TLS settings. Redact credentials.

# 14. MODULE 6 --- WEBSITE AND SSL MONITORING

Discover domains from CyberPanel metadata and validated virtual-host
configuration. Allow manual include/exclude rules.

For each domain: - DNS resolution. - HTTP and HTTPS checks. - Expected
status code. - Response time. - Redirect chain. - HTTPS redirect
behavior. - TLS validity and expiry. - Connection errors and timeouts.

Use bounded concurrency, safe request rates, and short timeouts. Allow
expected status codes to be configured per website.

Default certificate expiry levels: - Warning: 30 days. - High: 14
days. - Critical: 7 days. - Expired/invalid: critical.

External website checks must be performed by an independent provider or
monitor.

# 15. MODULE 7 --- CYBERPANEL AND WORDPRESS DISCOVERY

Automatically discover websites and WordPress installations. Do not
assume a single directory layout.

For each installation, identify: - Domain. - Document root. - Linux
owner/group. - `wp-config.php` path (do not expose its contents). -
WordPress version. - PHP version where discoverable. - Plugin
inventory. - Theme inventory. - Active plugin/theme status. -
Administrator count and changes. - Checksum status. - Update
availability. - Suspicious file indicators.

Use WP-CLI when available. Execute it as the website's owning Linux
user, not root.

Potential commands:

``` bash
wp core version
wp core check-update
wp core verify-checksums
wp plugin list --format=json
wp theme list --format=json
wp user list --role=administrator --fields=ID,user_login,user_email,roles --format=json
```

Use explicit `--path`, safe working directory, validated owner identity,
and command timeouts.

Do not collect passwords, password hashes, salts, or full configuration
files.

# 16. MODULE 8 --- WORDPRESS VULNERABILITY INTELLIGENCE

Implement a provider interface for vulnerability intelligence.

Support a documented provider such as WPScan or another authorized data
source. Do not scrape undocumented endpoints.

Requirements: - API key from protected secret file. - Rate-limit
handling. - Local cache. - Provider/database timestamp. - Version-aware
matching. - Clear source attribution. - Configurable provider. -
Graceful behavior when API is unavailable.

Finding states: - Confirmed vulnerable version. - Potentially
affected. - Update available. - No known vulnerability returned by the
queried source. - Lookup unavailable.

Never interpret an empty response as proof of safety.

# 17. MODULE 9 --- MALWARE AND SUSPICIOUS FILE SCANNING

Implement a layered scanning engine:

1.  Custom heuristic scanner.
2.  ClamAV.
3.  Lynis.
4.  rkhunter and/or chkrootkit.
5.  WordPress core checksum checks.
6.  File integrity monitoring.

Custom scanner indicators: - PHP files in uploads/temp locations. -
Unexpected executable files. - Suspicious obfuscation patterns. -
Unexpected recently created PHP files. - Hidden files in sensitive
directories. - Dangerous permissions. - Unexpected changes to WordPress
core. - Known webshell patterns from maintained rule sets.

Important: - `eval`, `base64_decode`, `shell_exec`, `system`,
`passthru`, and similar functions alone do not prove malware. - Every
result needs confidence, severity, evidence, and a reason. - Exclude
known cache, backup, vendor, and generated directories through
configuration. - Do not follow symlinks outside approved scan roots. -
Enforce maximum file size, depth, runtime, and concurrency. - Never
execute suspicious files. - Do not delete or quarantine files. - Do not
put full file contents in reports. - Record scanner errors and skipped
paths. - Mark interrupted or incomplete scans as incomplete, not clean.

ClamAV: - Check daemon/CLI availability. - Check signature database
freshness. - Support quick and full scan profiles. - Run full scans in
low-traffic windows. - Apply resource limits. - Record version,
signatures timestamp, duration, exit status, and findings.

Lynis: - Run scheduled host security audits. - Record version,
timestamp, exit status, and summary. - Treat recommendations as advisory
findings.

Rootkit: - Integrate rkhunter and/or chkrootkit if installed. - Record
tool version and warnings. - Explain false positives. - Do not claim
absence of rootkits based on a clean result alone.

# 18. MODULE 10 --- FILE AND SYSTEM INTEGRITY

Create an explicit baseline for configured critical files and
directories, such as:

``` text
/etc/passwd
/etc/group
/etc/sudoers
/etc/sudoers.d/
/etc/ssh/
/etc/crontab
/etc/cron.d/
/etc/systemd/system/
/etc/hosts
/etc/fstab
```

Also include selected CyberPanel/OpenLiteSpeed and WordPress critical
paths discovered at installation.

Store: - SHA-256 hash. - File type. - Size. - Owner/group. - Permission
mode. - Modification timestamp. - Baseline creation/update timestamp.

Detect additions, deletions, modifications, ownership changes, and
permission changes.

Baseline updates must require an explicit administrator action,
confirmation, and audit record. Never silently accept changes.

# 19. MODULE 11 --- SSH, FIREWALL, FAIL2BAN

Discover effective SSH settings and active SSH port.

Monitor: - Failed login counts. - Successful login counts. - Root login
events. - New/unusual login patterns. - Authentication method
configuration. - SSH configuration file changes. - Firewall status and
implementation. - Public listening ports. - Fail2Ban service. - Enabled
jails. - Ban counts and repeated offenders.

Do not assume SSH is on port 22 or CyberPanel on port 8090. Discover
actual ports.

Flag public exposure of MariaDB or Redis, while allowing documented
exceptions.

Do not change firewall rules or block IPs. Aggregate authentication
events and redact raw details in reports.

# 20. MODULE 12 --- FINDINGS, SCORING, AND COVERAGE

Every finding must contain:

-   Unique ID.
-   Category.
-   Check ID.
-   Asset/domain.
-   Severity.
-   Confidence.
-   First seen.
-   Last seen.
-   Status.
-   Evidence summary.
-   Recommended action.
-   Source/tool version.
-   Deduplication fingerprint.

Severity: - INFO - LOW - MEDIUM - HIGH - CRITICAL

Confidence: - LOW - MEDIUM - HIGH - CONFIRMED

Status: - OPEN - ACKNOWLEDGED - RESOLVED - SUPPRESSED

Implement two independent scores.

Server Health Score weights: - CPU/load: 20%. - RAM/swap: 20%. -
Disk/inodes: 15%. - Service availability: 20%. - MariaDB/Redis: 10%. -
Website availability: 15%.

Security Score weights: - SSH/authentication: 15%. - Firewall/network:
15%. - Malware/file integrity: 25%. - WordPress security: 25%. - System
integrity: 10%. - Vulnerability/patch status: 10%.

Scores must be deterministic and documented. Unknown checks reduce
coverage and must not count as passing. Display score, coverage, last
successful scan, and open findings together.

# 21. MODULE 13 --- ALERT MANAGEMENT

Send immediate email alerts for configured critical incidents: -
OpenLiteSpeed down. - MariaDB down. - Server health emergency. - Disk
emergency. - Very low available memory. - Confirmed malware. - Critical
file integrity change. - Expired/invalid SSL. - Website outage. -
External heartbeat loss (detected externally).

Implement: - Finding fingerprint deduplication. - Cooldown. - Alert
grouping. - Recovery notifications. - Escalation policy. - Retry with
bounded exponential backoff. - Delivery history. - Per-category
configuration.

Do not send one email for every repeated metric sample.

# 22. MODULE 14 --- EMAIL REPORTING

Default recipient:

``` text
rohmataliwardani@gmail.com
```

SMTP must be configurable: - Host. - Port. - Username. - Password
file/environment secret. - STARTTLS or implicit TLS. - Sender
name/address. - Recipient list. - Timeout. - Retry count.

Example Gmail SMTP configuration: - Host: `smtp.gmail.com` - Port:
`587` - Security: STARTTLS

Use a Gmail App Password where permitted. Do not hard-code the sender
account or password. Store secrets in root-owned mode `0600` files.

Email body: HTML summary.\
Attachment: full PDF report.

Weekly report: - Every Monday at 07:00 Asia/Jakarta. - Covers the
previous Monday through Sunday.

Monthly report: - Every first day of the month at 07:00 Asia/Jakarta. -
Covers the previous calendar month.

Weekly report sections: 1. Executive summary. 2. Health/security score
and coverage. 3. CPU/RAM/swap/disk trends. 4. Service status and
incidents. 5. OpenLiteSpeed errors. 6. MariaDB and Redis. 7. Website
uptime and SSL. 8. WordPress core/plugin/theme status. 9.
SSH/firewall/Fail2Ban. 10. Malware and file integrity. 11. Top issues.
12. Recommendations. 13. Scan coverage and unavailable checks.

Monthly report additionally: - Month-over-month comparisons. - Average
and peak metrics. - Daily trends. - Website uptime. - Disk growth. -
Incident trends. - Repeated findings. - Resolved/open findings. -
Scanner coverage and data gaps.

Subject examples:

``` text
[WEEKLY][hostname] Server Health & Security Report - YYYY-MM-DD
[MONTHLY][hostname] Server Health & Security Report - YYYY-MM
[CRITICAL][hostname] Server Monitoring Alert
```

# 23. MODULE 15 --- EXTERNAL MONITORING

External monitoring must be independent of the monitored server.

Implement a generic HTTPS heartbeat adapter: - Configurable endpoint. -
Token from protected secret file. - TLS certificate verification
enabled. - Request timeout. - Retry policy. - Signed or
bearer-token-authenticated payload. - Test command. - Delivery status.

Payload may include: - Random server ID. - Timestamp. - Application
version. - Overall status. - Coarse health summary. - Signature.

Do not send secrets, file contents, raw logs, database content, or
detailed login IP lists.

Document integration with an external provider or separately hosted
Uptime Kuma. If a provider-specific push adapter is implemented,
document its exact API and test it.

The external provider must detect stale/missing heartbeat even when the
monitored server is fully offline. Do not host the only heartbeat
receiver on the monitored server.

# 24. SQLITE DATABASE

Use SQLite with: - Versioned migrations. - WAL mode. - Foreign keys. -
Busy timeout. - Transactions. - Parameterized SQL. - Indexes. - Safe
backup/restore.

Create tables for: - schema migrations. - server information. - metric
samples. - hourly/daily metric rollups. - service checks. - websites. -
website checks. - SSL certificates. - WordPress sites. - WordPress
plugins. - WordPress themes. - WordPress audits. - security findings. -
file integrity baselines. - file integrity events. - scan runs. - log
cursors. - alerts. - alert deliveries. - reports. - report deliveries. -
external heartbeats. - administrative audit log.

Store timestamps in UTC; render them in Asia/Jakarta.

Retention defaults: - Raw metrics: 30 days. - Hourly rollups: 90 days. -
Daily rollups: 12 months. - Security findings: at least 12 months. -
Reports/delivery history: 12 months. - Integrity history: at least 180
days.

Preserve open findings and important security evidence. Use SQLite's
backup API or a consistent snapshot, not an unsafe live file copy.

# 25. SYSTEMD SCHEDULING

Create independent service/timer units.

Suggested schedule:

  Job                        Interval
  -------------------------- ----------------------------
  CPU/RAM/load               1 minute
  Service checks             1 minute
  MariaDB/Redis              5 minutes
  Website checks             5--15 minutes
  SSL                        6 hours
  SSH log aggregation        5--15 minutes
  OpenLiteSpeed log parser   5 minutes
  WordPress discovery        6 hours
  WordPress audit            Daily
  Incremental integrity      6--12 hours
  ClamAV quick scan          Daily
  Lynis audit                Weekly
  ClamAV full scan           Weekly, low-traffic period
  Rootkit scan               Weekly
  Weekly report              Monday 07:00
  Monthly report             Day 1 at 07:00
  External heartbeat         1--5 minutes

Use `Persistent=true` for appropriate timers. Handle missed schedules
safely. Prevent overlap using locks. Do not launch full scans
concurrently.

Apply `nice` and `ionice` where available for heavy scans. Do not impose
systemd CPU/memory limits without testing that they are compatible with
the target host.

# 26. RESOURCE TARGETS

Design for a modest VPS, for example 4 vCPU and 8 GB RAM, hosting many
WordPress sites.

Engineering targets: - Normal collector CPU overhead ideally below 2%
average. - Normal short-lived collector memory ideally below 200 MB. -
Bounded HTTP concurrency. - Bounded scanner concurrency. - Timeouts for
all commands and network calls. - Incremental log processing. - No full
filesystem scan every minute. - No expensive database queries at high
frequency. - No concurrent full scans.

Measure resource consumption during tests and report actual results. Do
not claim targets were met without measurements.

# 27. REQUIRED CLI COMMANDS

Implement at least:

``` bash
shsm --version
shsm --help
shsm status
shsm doctor
shsm config validate
shsm config show --redacted

shsm collect health
shsm collect services
shsm collect databases

shsm websites discover
shsm websites check

shsm wordpress discover
shsm wordpress audit

shsm security scan --profile quick
shsm security scan --profile full

shsm integrity status
shsm integrity baseline --review

shsm alerts list
shsm alerts test

shsm email test
shsm external test

shsm report weekly --preview
shsm report weekly --send
shsm report monthly --preview
shsm report monthly --send

shsm database backup
shsm retention run
```

Requirements: - Every command has `--help`. - Human-readable output by
default. - Optional `--json` output for automation. - Predictable exit
codes. - Useful error messages. - Consequential operations require
explicit flags and confirmation. - Preview and send modes are separate.

# 28. INSTALLER, UPGRADER, UNINSTALLER

Implement `install.sh`, `upgrade.sh`, `uninstall.sh`, and
`self_test.sh`.

## Installer

1.  Detect Ubuntu version and architecture.
2.  Check Python version.
3.  Check available disk and memory.
4.  Discover CyberPanel/OpenLiteSpeed paths.
5.  Detect MariaDB, Redis, WP-CLI, ClamAV, Lynis, rootkit tools.
6.  Check systemd availability.
7.  Show a preflight plan.
8.  Ask for confirmation.
9.  Create isolated Python virtual environment.
10. Install pinned dependencies.
11. Create service account and directories.
12. Apply secure permissions.
13. Create initial configuration without overwriting existing files.
14. Install systemd units/timers.
15. Initialize SQLite migrations.
16. Run self-test.
17. Print exact next steps.

Do not modify CyberPanel, OpenLiteSpeed, MariaDB, Redis, SSH, or
firewall configuration.

## Upgrader

-   Back up configuration and database.
-   Preserve reports and baselines.
-   Apply migrations safely.
-   Upgrade pinned dependencies.
-   Verify service/timer health.
-   Roll back or provide recovery instructions if upgrade fails.

## Uninstaller

-   Stop and disable SHSM timers/services.
-   Remove application code and units after confirmation.
-   Preserve configuration, database, reports, and baselines by default.
-   Data deletion must require a separate explicit confirmation.
-   Never remove unrelated system packages or hosting components.

# 29. TESTING REQUIREMENTS

Write real automated tests using fixtures and mocks.

Unit tests: - Metric parsing. - Threshold windows. - Score and
coverage. - Timezone and reporting boundaries. - Finding
deduplication. - Log rotation/truncation. - Path validation. - Symlink
escape prevention. - Secret redaction. - HTML escaping. - SQLite
migrations. - Retention. - Alert cooldown/recovery. - Retry behavior.

Integration tests: - Mocked Linux command outputs. - MariaDB and Redis
connectivity. - OpenLiteSpeed log fixtures. - SSH authentication log
fixtures. - CyberPanel website discovery fixtures. - WordPress test
installation. - WP-CLI non-root execution. - ClamAV
missing/outdated/error states. - SMTP success/failure. - External
heartbeat success/failure. - systemd unit installation.

Failure tests: - Network unavailable. - SMTP unavailable. - Disk nearly
full. - SQLite locked or corrupt. - Scanner timeout. - Log rotation. -
Website timeout. - Missing WP-CLI. - Permission denied. - Missing or
renamed service. - Reboot and missed timer execution.

Never run destructive tests against a live production host.

# 30. DOCUMENTATION AND HANDOVER

Create: - README.md. - Installation guide. - Configuration guide. - CLI
reference. - Security and permissions guide. - External monitoring
setup. - SMTP setup. - Backup and restore. - Upgrade and uninstall. -
Troubleshooting. - False-positive handling. - Scanner limitations. -
systemd timer reference. - Sample redacted weekly report. - Sample
redacted monthly report. - Dependency inventory.

# 31. REQUIRED DEVELOPMENT WORKFLOW

Follow this sequence and maintain a checklist:

**Phase 1 --- Repository and environment inspection** - Inspect current
files. - Identify existing project conventions. - Preserve existing
work. - Confirm supported environment. - Create implementation
checklist.

**Phase 2 --- Foundation** - Package configuration. - CLI. - YAML
validation. - Logging and redaction. - Safe subprocess runner. -
Locks. - SQLite and migrations.

**Phase 3 --- Core health** - CPU/RAM/swap. - Disk/inodes. -
Process/network. - Service monitoring. - MariaDB/Redis.

**Phase 4 --- Hosting and websites** - CyberPanel discovery. -
OpenLiteSpeed monitoring. - Website HTTP/DNS/SSL. - WordPress discovery
and audit.

**Phase 5 --- Security** - SSH. - Firewall. - Fail2Ban. - Malware
heuristics. - ClamAV. - Lynis. - Rootkit adapters. - File/system
integrity. - Vulnerability intelligence adapter.

**Phase 6 --- Findings and notification** - Findings. - Scoring and
coverage. - Alert deduplication. - SMTP. - External heartbeat.

**Phase 7 --- Reporting** - Weekly report. - Monthly report. - HTML
email. - PDF attachment. - Preview/send workflows.

**Phase 8 --- Deployment** - systemd units/timers. - Installer. -
Upgrader. - Uninstaller. - Self-test. - Backup/restore.

**Phase 9 --- Verification** - Run unit tests. - Run integration
tests. - Run lint and type checks. - Perform security review. - Measure
resource usage. - Verify sample reports. - Verify reboot recovery. -
Document all failures and limitations.

Do not mark a phase complete while required modules are placeholders.

# 32. DEFINITION OF DONE

The project is complete only when:

1.  The CLI installs and executes successfully.
2.  Configuration validation works.
3.  SQLite migrations work on a clean installation and an upgrade.
4.  All implemented collectors return structured results.
5.  WordPress discovery does not execute WP-CLI as root.
6.  Scanner errors and incomplete scans are represented honestly.
7.  No automatic destructive remediation exists.
8.  Alerts are deduplicated and recovery is supported.
9.  Weekly and monthly periods are correct in Asia/Jakarta.
10. SMTP test and report delivery work with configured credentials.
11. External heartbeat test reaches the independent endpoint.
12. A remote monitor can detect missing heartbeats while the host is
    offline.
13. systemd timers survive reboot and handle missed runs.
14. Installer does not overwrite hosting configuration.
15. Uninstaller preserves data by default.
16. Secrets are redacted everywhere.
17. Unit and integration tests pass, with results documented.
18. Resource overhead is measured.
19. Documentation is complete.
20. No unresolved critical security or data-loss defect remains.

# 33. FINAL RESPONSE EXPECTED FROM THE CODING AGENT

At the end of implementation, provide a concise but complete handover:

-   Summary of implemented features.
-   Project tree.
-   Supported Ubuntu/Python versions.
-   Installation command.
-   Configuration steps.
-   SMTP setup.
-   External monitor setup.
-   systemd timers and schedules.
-   CLI command examples.
-   Test results with passed/failed counts.
-   Actual resource measurements.
-   Known limitations and unimplemented integrations.
-   False-positive guidance.
-   Backup/restore instructions.
-   Upgrade/uninstall instructions.
-   Production deployment checklist.

Be honest. Never claim a feature is implemented, tested, secure, or
operational unless the code and test evidence support that statement.

------------------------------------------------------------------------

# START IMPLEMENTATION

First inspect the repository and target environment. Then create the
implementation checklist and begin Phase 1.

Do not respond with another proposal or ask the user to approve the
already-fixed architecture. Implement the application according to this
specification. Ask a question only if a missing credential, external
endpoint, or genuinely ambiguous server-specific detail prevents safe
progress. Use clearly documented placeholders for secrets and external
endpoints, and continue implementing all independent components.
