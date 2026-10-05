# Server Health & Security Monitoring (SHSM)

## Final Technical Specification & Master Development Prompt

**Project owner:** GM Teknologi\
**Primary recipient:** rohmataliwardani@gmail.com\
**Target platform:** Ubuntu Server + CyberPanel + OpenLiteSpeed +
MariaDB + Redis + multiple WordPress installations\
**Application interface:** CLI only (v1)\
**Architecture:** Single-server agent with external uptime/heartbeat
monitoring\
**Timezone:** Asia/Jakarta\
**Document status:** Approved implementation baseline

------------------------------------------------------------------------

# PART I --- FINAL TECHNICAL SPECIFICATION

## 1. Project objective

Build a production-ready, lightweight, security-focused monitoring
application that runs locally on an Ubuntu server hosting CyberPanel,
OpenLiteSpeed, MariaDB, Redis, and multiple WordPress websites.

The application must:

1.  Continuously collect server health metrics.
2.  Monitor critical services and website availability.
3.  Audit host security and detect suspicious activity.
4.  Discover and audit WordPress installations automatically.
5.  Monitor OpenLiteSpeed, MariaDB, and Redis.
6.  Generate weekly and monthly HTML/PDF reports.
7.  Send reports and critical alerts through configurable SMTP.
8.  Report server availability to an external monitoring endpoint so a
    complete server outage can still be detected.
9.  Operate with minimal resource consumption and safe read-only
    defaults.
10. Be installable, configurable, upgradeable, testable, and
    uninstallable through documented scripts.

The v1 product is CLI-only. Do not build a web dashboard, public API, or
listening web service.

## 2. Approved implementation decisions

  -----------------------------------------------------------------------
  Area                                Final decision
  ----------------------------------- -----------------------------------
  Interface                           CLI

  Runtime                             Python 3

  Local data store                    SQLite

  Scheduling                          systemd services and timers

  Local monitoring                    Python monitoring agent

  Security scanning                   Custom checks + ClamAV + Lynis +
                                      rkhunter and/or chkrootkit

  WordPress inspection                WP-CLI, executed as the website
                                      owner

  Webserver                           OpenLiteSpeed

  Database                            MariaDB

  Cache                               Redis

  Reports                             HTML email + PDF attachment

  Email                               Configurable SMTP, STARTTLS or
                                      implicit TLS

  Recipient                           rohmataliwardani@gmail.com by
                                      default

  External monitoring                 Yes; heartbeat plus externally
                                      executed HTTP/SSL checks

  Deployment                          Single server

  Security posture                    Read-only by default

  Timezone                            Asia/Jakarta

  Retention                           Configurable; default 12 months for
                                      report/event records
  -----------------------------------------------------------------------

## 3. Supported environment and compatibility

Target Ubuntu 20.04 LTS or newer, subject to dependency compatibility
and security support status. The installer must detect the exact OS
release and must not silently assume package availability.

The application must detect rather than hard-code:

-   CyberPanel installation paths and service names.
-   OpenLiteSpeed binary, configuration, log, and PID paths.
-   MariaDB service name, socket, and client binary.
-   Redis service name, endpoint, and authentication requirements.
-   CyberPanel website document roots and domain ownership.
-   SSH port and effective SSH configuration.
-   Active firewall implementation: nftables, UFW, or firewalld.
-   Fail2Ban installation, service, and enabled jails.
-   PHP versions and WP-CLI availability.

Do not assume every server uses the same service names, ports, directory
layout, PHP version, or log format. Implement discovery with safe
fallbacks and record unresolved checks as `UNKNOWN`, not `PASS`.

The system must support multi-domain CyberPanel layouts and avoid
scanning unrelated system directories indiscriminately.

## 4. Architecture

### 4.1 Local architecture

``` text
systemd timers
     |
     v
SHSM CLI / scheduler entry points
     |
     +--> Host health collectors
     +--> Service collectors
     +--> OpenLiteSpeed log analyzer
     +--> MariaDB and Redis collectors
     +--> Website and SSL checks
     +--> WordPress discovery and audit
     +--> Security audit and scanners
     |
     v
Normalization and finding engine
     |
     +--> Threshold evaluation
     +--> Severity and confidence classification
     +--> Deduplication and correlation
     +--> Health and security scoring
     |
     v
SQLite database
     |
     +--> Alert manager --> SMTP
     +--> Weekly/monthly report generator --> SMTP
     +--> Heartbeat sender --> External monitor
```

### 4.2 External monitoring architecture

The local agent sends a signed or token-authenticated heartbeat to an
external monitoring service. An external service must independently
monitor:

-   Heartbeat freshness.
-   Public server reachability where possible.
-   Selected website HTTP status.
-   TLS certificate validity and expiry.
-   Optional DNS resolution.

A heartbeat endpoint hosted only on the monitored server is not
sufficient. If the server is offline, that endpoint is also offline. Use
an independent provider or a separately hosted Uptime Kuma instance.

The external monitoring provider must be configurable. Do not hard-code
a vendor. Implement a generic HTTPS webhook adapter and, if selected, a
documented Uptime Kuma-compatible push integration. Never claim an
external monitor is configured until an actual endpoint and token have
been supplied and a test succeeds.

Heartbeat payload should contain only: - Random server identifier. -
Timestamp. - Application version. - Overall status. - Optional coarse
health values. - HMAC signature or bearer-token authentication.

Do not send credentials, file contents, website source code, database
contents, IP login lists, or sensitive log excerpts in heartbeat
payloads.

### 4.3 Execution model

Use short-lived, independently executable CLI commands invoked by
systemd timers. Avoid a permanently running Python scheduler unless a
specific feature requires it.

Suggested commands:

``` text
shsm install-check
shsm status
shsm collect health
shsm collect services
shsm scan security --profile quick
shsm scan security --profile full
shsm wordpress discover
shsm wordpress audit
shsm websites check
shsm reports weekly --send
shsm reports monthly --send
shsm alerts test
shsm email test
shsm external test
shsm database backup
shsm config validate
```

Every command must support `--help`, structured exit codes, timeouts,
and useful log messages.

## 5. Functional modules

### 5.1 Host health monitoring

Collect:

-   CPU utilization overall and per core.
-   Load average for 1, 5, and 15 minutes.
-   CPU iowait and steal where available.
-   RAM total, used, available, cache, and buffers.
-   Swap total, used, and activity.
-   Filesystem usage and free space.
-   Inode usage.
-   Disk I/O and utilization where supported.
-   Network interface counters.
-   Uptime and reboot history.
-   Top CPU and memory processes.
-   OOM-killer events.
-   Failed systemd units.

Default thresholds (all configurable):

  Metric                   Warning         Critical         Emergency
  --------------- ---------------- ---------------- -----------------
  CPU sustained     \>= 80% for 5m   \>= 90% for 5m   \>= 95% for 10m
  RAM available             \< 20%           \< 10%             \< 5%
  Disk usage               \>= 80%          \>= 90%           \>= 95%
  Inode usage              \>= 80%          \>= 90%           \>= 95%
  Swap usage               \>= 50%          \>= 75%           \>= 90%
  Load per CPU             \>= 1.5          \>= 2.0           \>= 3.0

Thresholds must be configurable and interpreted in context. CPU steal
and iowait require separate findings. Linux page cache must not be
treated as unavailable memory; use `MemAvailable` when present.

Do not create alerts from one isolated sample for metrics requiring
sustained duration. Store samples and evaluate rolling windows.

### 5.2 Process and service monitoring

Monitor discovered services, including where installed:

-   OpenLiteSpeed / LiteSpeed.
-   CyberPanel-related services.
-   MariaDB.
-   Redis.
-   SSH.
-   Fail2Ban.
-   Active firewall service.
-   Cron/systemd timers.
-   Other explicitly configured critical services.

Record service state, PID, restart count if available, uptime, and
recent failure reason.

Detect: - Service unexpectedly stopped. - Repeated restart loops. -
Unexpected new systemd unit files. - Unexpected privileged processes. -
Zombie process growth. - Unusual CPU or memory consumption.

Do not restart services automatically in v1.

### 5.3 OpenLiteSpeed monitoring

Discover OpenLiteSpeed installation and logs. Monitor:

-   Service availability and process state.
-   Access and error log growth.
-   HTTP 5xx counts and rates.
-   PHP fatal errors and memory exhaustion.
-   Timeout and upstream errors.
-   SSL handshake errors.
-   Virtual-host-level error concentration.
-   Request patterns against common WordPress endpoints.
-   Restart events and abnormal process exits.

Parse logs incrementally using persisted file identity, inode, and byte
offset. Handle log rotation, truncation, and changed inode safely. Do
not reread all historical logs on every run.

Provide configurable log paths and parsers. Treat log content as
untrusted data. Escape it before placing any excerpts into HTML reports.

### 5.4 MariaDB monitoring

Use a dedicated least-privilege monitoring account. Prefer local socket
authentication or a protected option file. Never place database
passwords in command-line arguments.

Collect: - Service status and uptime. - Connections and max
connections. - Aborted connections. - Slow query counters and configured
slow-log path. - InnoDB buffer pool indicators. - Deadlock indicators
where safely available. - Database size estimates. - Error log events.

Use lightweight status queries. Avoid frequent `SHOW FULL PROCESSLIST`
or expensive table scans. Do not collect query text by default because
it can contain sensitive information.

### 5.5 Redis monitoring

Collect: - PING availability and latency. - Memory used and configured
maximum. - Connected clients. - Cache hit/miss counters. - Evicted
keys. - Expired keys. - Persistence status. - Uptime and connection
errors.

Respect Redis authentication and TLS configuration. Never expose
credentials in logs or reports.

### 5.6 Website availability and SSL

Discover website domains from CyberPanel metadata and validated
virtual-host configuration. Allow manual include/exclude overrides.

For each configured domain: - DNS resolution. - HTTP and HTTPS
response. - Response time. - Redirect chain and HTTPS redirect
behavior. - Expected status code. - TLS certificate validity and
expiry. - Connection and DNS errors.

Use bounded concurrency, request timeouts, and a configurable check
interval. Do not send aggressive requests to hosted websites. Avoid
treating expected authentication-protected or intentionally non-200
pages as outages; allow expected status codes per domain.

SSL expiry defaults: - Warning: 30 days. - High: 14 days. - Critical: 7
days. - Critical/expired: 0 days or invalid certificate.

External checks should be performed by the independent external
monitoring provider, not merely by the local process.

### 5.7 WordPress discovery and auditing

Discover WordPress installations using CyberPanel domain metadata and
known document-root patterns. Validate each candidate by locating
`wp-config.php` and verifying WordPress structure.

For each installation, record: - Domain and document root. - Linux owner
and group. - WordPress version. - PHP CLI/runtime version where
discoverable. - Core update availability. - Plugin and theme
inventory. - Active/inactive status. - Administrator count and
changes. - Checksum verification result. - Relevant file permission
anomalies. - Upload directory PHP/executable file findings.

Use WP-CLI where available. Execute WP-CLI as the owning website user,
with a safe working directory and explicit path. Do not execute
arbitrary PHP as root. Do not load a website's plugins/themes for
routine discovery unless necessary.

Commands may include:

``` bash
wp core version
wp core check-update
wp core verify-checksums
wp plugin list --format=json
wp theme list --format=json
wp user list --role=administrator --fields=ID,user_login,user_email,roles --format=json
```

Use command timeouts and sanitize outputs. Avoid collecting password
hashes, salts, secrets, or full `wp-config.php` content.

Plugin/theme vulnerability intelligence must use a configured,
documented data source or API. Cache results, respect rate limits and
licensing, record database timestamp, and distinguish: - Confirmed
vulnerable version. - Potentially affected version. - Update
available. - No known vulnerability in the queried source. - Lookup
unavailable.

Do not state that a plugin is safe merely because no vulnerability
result was returned.

### 5.8 Malware and suspicious-file detection

Use a layered approach:

1.  Custom heuristic scanner.
2.  ClamAV signature scanning.
3.  Lynis host security audit.
4.  rkhunter and/or chkrootkit rootkit checks.
5.  WordPress core checksum verification.
6.  File-integrity baseline and change detection.

Custom rules may flag: - PHP files in uploads or temporary
directories. - Unexpected executable files. - Suspicious obfuscated code
patterns. - Unexpected recently created PHP files. - Hidden files in
sensitive paths. - Dangerous permissions. - Unexpected modifications to
core files. - Known webshell or malware signatures from maintained rule
sets.

Important safeguards: - A function such as `eval`, `base64_decode`,
`shell_exec`, or `system` is not proof of malware. - Assign confidence
and evidence to every finding. - Exclude known legitimate cache, backup,
vendor, and generated directories through explicit configuration. - Do
not follow symlinks outside approved scan roots. - Apply file size,
depth, time, and concurrency limits. - Do not execute suspicious
files. - Do not delete, quarantine, chmod, or modify files
automatically. - Store file path, size, timestamps, hash, rule ID, and
limited safe evidence. Avoid copying full source code into reports. -
Provide a manual review workflow and documented false-positive
suppression mechanism.

ClamAV must be installed and its signature database freshness checked.
Full scans should be scheduled during low-traffic periods and
rate-limited. Record skipped files and scanner errors; never report a
clean scan if the scanner did not complete.

Lynis, rkhunter, and chkrootkit outputs are advisory signals and can
produce false positives. Preserve tool version, scan time, exit code,
and summary.

### 5.9 File integrity and system integrity

Create a baseline for explicitly configured critical files and
directories, including:

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

Also monitor selected WordPress critical files and
CyberPanel/OpenLiteSpeed configuration paths discovered at install time.

Store SHA-256 hashes and metadata. Baseline creation and updates must
require explicit administrator action. Protect baseline files with
root-only permissions. Detect additions, modifications, deletions,
ownership changes, and permission changes.

Do not silently accept changed files into the baseline. Provide an
explicit command such as `shsm integrity baseline --review` with
confirmation and audit record.

### 5.10 SSH, firewall, and Fail2Ban

Inspect: - Effective SSH configuration. - Password and root login
settings. - Listening SSH port. - Failed and successful authentication
events. - New or unusual login patterns. - Firewall implementation and
active rules. - Public listening ports. - Fail2Ban service and jail
status. - Ban counts and repeated offenders.

Do not assume SSH port 22 or CyberPanel port 8090. Discover actual
configuration. Do not print sensitive authentication log contents in
email; aggregate counts and redact where needed.

Flag publicly exposed MariaDB or Redis ports, but account for
intentional and documented architectures. Do not alter firewall rules or
ban addresses automatically.

### 5.11 Security audit

Run Lynis on a controlled schedule. Use ClamAV and rootkit scanners
according to their own schedules. Capture tool version, start/end time,
exit status, summary, and errors.

Do not run all full scanners simultaneously. Implement a global scan
lock and configurable resource limits. The scan must be cancellable and
must not overlap with another full scan.

## 6. Scoring and finding model

Maintain separate scores:

-   Server Health Score: 0--100.
-   Security Score: 0--100.

Scores are summaries, not guarantees of safety. Every score must be
accompanied by findings, coverage, and data freshness.

Suggested health weights: - CPU/load: 20%. - RAM/swap: 20%. -
Disk/inodes: 15%. - Service availability: 20%. - Database/cache: 10%. -
Website availability: 15%.

Suggested security weights: - SSH/authentication: 15%. -
Firewall/network: 15%. - Malware/file integrity: 25%. - WordPress
security: 25%. - System integrity: 10%. - Vulnerability/patch status:
10%.

Implement deterministic penalties by severity and confidence.
Unknown/unavailable checks must reduce coverage, not be treated as
passing. Show score coverage percentage and last successful scan
timestamp.

Finding fields: - Unique ID. - Category and check ID. - Asset/domain. -
Severity: INFO, LOW, MEDIUM, HIGH, CRITICAL. - Confidence: LOW, MEDIUM,
HIGH, CONFIRMED. - First seen and last seen. - Status: OPEN,
ACKNOWLEDGED, RESOLVED, SUPPRESSED. - Evidence summary. - Recommended
action. - Source/tool version. - Deduplication fingerprint.

## 7. Alerts and notification policy

Send immediate alerts for configured critical events: - Server heartbeat
loss (external monitor). - OpenLiteSpeed or MariaDB down. - Disk
emergency threshold. - Very low available RAM. - Confirmed malware
finding. - Critical file-integrity change. - Expired/invalid TLS
certificate. - Repeated website outage.

Implement: - Deduplication. - Cooldown. - Recovery notification. -
Escalation. - Per-category enable/disable. - Alert history. - SMTP retry
with bounded exponential backoff. - Failure queue and delivery status.

Never send one email for every repeated sample. Group related events
into a concise alert.

## 8. Weekly and monthly reports

Default recipient: `rohmataliwardani@gmail.com`.

Weekly report: - Every Monday at 07:00 Asia/Jakarta. - Covers the
previous Monday 00:00 through Sunday 23:59:59 local time.

Monthly report: - Day 1 at 07:00 Asia/Jakarta. - Covers the entire
previous calendar month.

Reports must use the period's stored data, not just current state.

Weekly report sections: 1. Executive summary. 2. Health and security
scores with coverage. 3. CPU, RAM, swap, disk trends. 4. Service
incidents and downtime. 5. OpenLiteSpeed error summary. 6. MariaDB and
Redis health. 7. Website availability and SSL. 8. WordPress
core/plugin/theme findings. 9. SSH/firewall/Fail2Ban summary. 10.
Malware and file-integrity findings. 11. Top issues and recommended
actions. 12. Scan coverage and skipped checks.

Monthly report additionally includes: - Month-over-month comparisons. -
Daily/hourly trends. - Peak and average resource usage. - Website uptime
summary. - Disk growth. - Incident trends. - Repeated findings. -
Resolved versus open findings. - Scanner coverage and data gaps.

Email format: - HTML summary in email body. - Full PDF attachment. -
Clear hostname and reporting period. - Generation timestamp and
timezone. - Score coverage and last scan times. - No secrets or full
sensitive log lines.

Subject examples:

``` text
[WEEKLY][gmteknologi] Server Health & Security Report - YYYY-MM-DD
[MONTHLY][gmteknologi] Server Health & Security Report - YYYY-MM
[CRITICAL][gmteknologi] Server Monitoring Alert
```

## 9. SMTP configuration

Support configurable SMTP settings: - Host. - Port. - Username. -
Password or app password via protected secret file/environment. -
STARTTLS or implicit TLS. - Sender name and address. - Recipient list. -
Connection timeout. - Retry policy.

Default recipient is `rohmataliwardani@gmail.com`. Do not hard-code
sender credentials. Provide a test command.

Example configuration:

``` yaml
email:
  enabled: true
  smtp_host: smtp.gmail.com
  smtp_port: 587
  security: starttls
  username: "monitoring-sender@example.com"
  password_file: "/etc/shsm/smtp_password"
  from_name: "GM Teknologi Server Monitor"
  from_address: "monitoring-sender@example.com"
  recipients:
    - "rohmataliwardani@gmail.com"
  timeout_seconds: 20
  retries: 3
```

Secret file must be root-owned and mode `0600`. Never include secret
values in diagnostic output.

## 10. SQLite data model

Implement schema migrations and indexes. Suggested tables:

-   `schema_migrations`
-   `server_info`
-   `metric_samples`
-   `metric_rollups_hourly`
-   `metric_rollups_daily`
-   `service_checks`
-   `websites`
-   `website_checks`
-   `ssl_certificates`
-   `wordpress_sites`
-   `wordpress_plugins`
-   `wordpress_themes`
-   `wordpress_audits`
-   `security_findings`
-   `file_integrity_baselines`
-   `file_integrity_events`
-   `security_scan_runs`
-   `log_cursors`
-   `alerts`
-   `alert_deliveries`
-   `reports`
-   `report_deliveries`
-   `external_heartbeats`
-   `audit_log`

Use UTC timestamps in storage and convert to Asia/Jakarta for display
and scheduling. Store numeric metrics in typed columns where practical.
Use parameterized SQL exclusively.

Use SQLite WAL mode, foreign keys, busy timeout, transaction boundaries,
and safe backup through SQLite's backup API or a consistent snapshot.
Never copy a live database file naïvely while writes are active.

Retention defaults: - Raw 1-minute/5-minute metrics: 30 days. - Hourly
rollups: 90 days. - Daily rollups: 12 months. - Security findings and
audit history: 12 months minimum, configurable. - Reports and delivery
records: 12 months. - Integrity event history: 180 days minimum,
configurable.

Retention must preserve open findings and important security evidence.

## 11. Scheduling

Use systemd timers with persistent execution after downtime. Suggested
schedule:

  Job                            Interval
  ------------------------------ ----------------------------
  Basic host metrics             1 minute
  Service health                 1 minute
  Database/cache health          5 minutes
  Website HTTP checks            5--15 minutes
  SSL checks                     6 hours
  SSH/security log aggregation   5--15 minutes
  OpenLiteSpeed log parsing      5 minutes
  WordPress discovery            6 hours
  WordPress audit                Daily
  Incremental integrity scan     6--12 hours
  Lynis audit                    Weekly
  ClamAV quick scan              Daily
  ClamAV full scan               Weekly, low-traffic window
  Rootkit scan                   Weekly
  Weekly report                  Monday 07:00
  Monthly report                 Day 1, 07:00
  External heartbeat             1--5 minutes

Use randomized delay where appropriate to avoid synchronized workload. A
global lock must prevent overlapping heavy scans. All timers must use
`Persistent=true` where appropriate and handle missed runs safely.

## 12. Resource and performance requirements

Design for a modest VPS (for example, 4 vCPU and 8 GB RAM) hosting many
WordPress sites.

Targets: - Idle/short collector CPU overhead: ideally below 2% average,
measured in testing. - Resident memory for normal CLI collection:
ideally below 200 MB. - Bounded website-check concurrency. - Bounded
scanner concurrency. - Timeouts for every subprocess and network
request. - Incremental log parsing. - No full filesystem scan every
minute. - No expensive database query in high-frequency jobs. - No
overlapping full scans. - Configurable CPU/IO priority using `nice` and
`ionice` where available.

These are engineering targets, not guarantees; benchmark on the actual
server.

## 13. Security requirements

-   Run privileged checks through a tightly scoped privilege model.
-   Avoid running WP-CLI as root.
-   Use subprocess argument arrays; never concatenate untrusted values
    into shell commands.
-   Validate and canonicalize all discovered paths.
-   Prevent path traversal and symlink escape.
-   Apply least privilege to MariaDB and Redis access.
-   Protect config, secrets, SQLite database, logs, reports, and
    baseline.
-   Redact credentials, tokens, salts, cookies, and sensitive log data.
-   Escape all untrusted data in HTML reports.
-   Validate TLS certificates for SMTP and external HTTPS.
-   Do not disable TLS verification.
-   Do not execute files detected by scanners.
-   No automatic deletion, quarantine, firewall changes, service
    restarts, or WordPress updates in v1.
-   Log administrative actions and baseline changes.
-   Pin and review dependencies.
-   Include software bill of materials or dependency inventory.
-   Provide secure uninstall behavior that does not delete
    reports/database unless explicitly requested.

## 14. Project directory layout

``` text
/opt/shsm/
  pyproject.toml
  requirements.lock
  README.md
  CHANGELOG.md
  LICENSE
  src/shsm/
    __init__.py
    cli.py
    config.py
    logging_config.py
    database/
      connection.py
      migrations/
      repositories/
    collectors/
      cpu.py
      memory.py
      disk.py
      process.py
      services.py
      network.py
      openlitespeed.py
      mariadb.py
      redis.py
      websites.py
      ssl.py
    security/
      ssh.py
      firewall.py
      fail2ban.py
      malware.py
      clamav.py
      lynis.py
      rootkit.py
      wordpress.py
      integrity.py
      vulnerability.py
    reporting/
      weekly.py
      monthly.py
      html.py
      pdf.py
      scoring.py
    notifications/
      smtp.py
      alerts.py
      external.py
    discovery/
      cyberpanel.py
      wordpress.py
      services.py
    core/
      runner.py
      locks.py
      findings.py
      retention.py
      subprocesses.py
      timeutils.py
  config/
    config.example.yaml
    thresholds.example.yaml
    paths.example.yaml
  templates/
    email/
    reports/
  scripts/
    install.sh
    upgrade.sh
    uninstall.sh
    self_test.sh
  systemd/
    shsm-*.service
    shsm-*.timer
  tests/
    unit/
    integration/
    fixtures/
```

Runtime data should be stored separately:

``` text
/etc/shsm/
  config.yaml
  secrets/
  rules/

/var/lib/shsm/
  monitoring.db
  baseline/
  state/

/var/log/shsm/
  shsm.log
  scan.log

/var/cache/shsm/

/var/lib/shsm/reports/
  weekly/
  monthly/
```

Use `/opt/shsm` for application code, `/etc/shsm` for configuration,
`/var/lib/shsm` for state/data, and `/var/log/shsm` for logs.

## 15. CLI command specification

At minimum implement:

``` text
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

Commands that can send email, update baselines, or perform consequential
operations must require explicit flags and confirmation where
appropriate.

## 16. Installation and operations

Provide: - `install.sh`: preflight, dependency checks, virtual
environment, package install, directories, permissions, systemd units,
initial configuration. - `upgrade.sh`: backup config/database, apply
migrations, upgrade package, restart timers safely, verify health. -
`uninstall.sh`: stop/disable timers and services, remove application
files only after confirmation; preserve data by default. -
`self_test.sh`: dependency, permission, database, SMTP configuration,
systemd, and external endpoint checks.

The installer must: 1. Detect Ubuntu release and architecture. 2. Check
disk space and memory. 3. Detect CyberPanel/OpenLiteSpeed paths. 4.
Check whether required packages are available. 5. Show a plan before
modifying the system. 6. Require explicit confirmation. 7. Avoid
overwriting existing configurations. 8. Create a dedicated service
account where compatible. 9. Install Python dependencies in an isolated
virtual environment. 10. Install systemd units with least privilege. 11.
Create a first-run configuration from a template. 12. Print exact next
steps and validation commands.

Never assume that installing packages or changing firewall rules is
harmless. Do not alter existing CyberPanel, OpenLiteSpeed, MariaDB,
Redis, SSH, or firewall configuration.

## 17. Testing and acceptance criteria

### Unit tests

-   Threshold calculations.
-   Timezone and reporting period boundaries.
-   Scoring and coverage.
-   Finding deduplication.
-   Log parser rotation/truncation.
-   Path validation and symlink protection.
-   HTML escaping.
-   Secret redaction.
-   SQLite migrations and retention.
-   Retry and cooldown behavior.

### Integration tests

-   Mocked system command outputs.
-   MariaDB and Redis test connections.
-   Sample OpenLiteSpeed logs.
-   Sample auth logs.
-   Sample WordPress installations.
-   WP-CLI execution as a non-root owner.
-   ClamAV unavailable/outdated/error scenarios.
-   SMTP success/failure.
-   External heartbeat success/failure.
-   systemd timer/service installation.

### Failure tests

-   Server reboot.
-   Network unavailable.
-   SMTP unavailable.
-   Disk nearly full.
-   SQLite locked/corrupt.
-   Scanner timeout.
-   Log rotation.
-   Website timeout.
-   Missing WP-CLI.
-   Permission denied.
-   Service absent or renamed.

### Acceptance criteria

-   No secret appears in logs, CLI output, HTML, or PDF.
-   Unknown checks are never reported as passing.
-   No automatic destructive remediation occurs.
-   All scheduled jobs are idempotent and lock-protected.
-   Missed systemd timer runs are handled safely.
-   Reports cover the correct previous week/month in Asia/Jakarta.
-   External monitoring can detect stale heartbeat independently.
-   Installer and uninstaller preserve existing hosting configuration.
-   Resource overhead is measured and documented.
-   Tests pass on the declared supported Ubuntu versions.

## 18. Delivery package

The completed project must include: 1. Full source code. 2. Dependency
lock file. 3. Example and production configuration templates. 4.
Database migrations. 5. systemd services and timers. 6. Installer,
upgrader, uninstaller, and self-test scripts. 7. CLI documentation. 8.
Security model and permission documentation. 9. Weekly and monthly
report templates. 10. Unit and integration tests. 11. Sample redacted
reports. 12. Troubleshooting guide. 13. Backup and restore guide. 14.
Release/versioning notes.

------------------------------------------------------------------------

# PART II --- MASTER DEVELOPMENT PROMPT

The following prompt is intended to be supplied to a coding agent or
software development AI. It defines the implementation scope and quality
requirements.

------------------------------------------------------------------------

## MASTER PROMPT: BUILD SHSM PRODUCTION-READY

### Role

Act as a senior Python engineer, Linux systems engineer, DevSecOps
architect, and application security specialist. Build a complete,
production-ready CLI application named **Server Health & Security
Monitoring (SHSM)** for Ubuntu servers running CyberPanel,
OpenLiteSpeed, MariaDB, Redis, and multiple WordPress websites.

Do not deliver only a plan, pseudocode, sample snippets, or a prototype.
Implement the complete application, tests, installation assets,
documentation, and operational configuration.

### A. Fixed product decisions

Follow these decisions exactly:

-   Interface: CLI only. Do not build a web dashboard.
-   Runtime: Python 3 with an isolated virtual environment.
-   Local database: SQLite with migrations, indexes, WAL mode, and
    retention.
-   Scheduler: systemd services and timers.
-   Security scanners: custom heuristic scanner, ClamAV, Lynis, rkhunter
    and/or chkrootkit.
-   WordPress integration: WP-CLI, executed as the website owner.
-   Local stack: CyberPanel, OpenLiteSpeed, MariaDB, Redis, Ubuntu.
-   External monitoring: independent heartbeat and external website/SSL
    checks.
-   Architecture: one monitored server in v1.
-   Reports: HTML email and PDF attachment.
-   SMTP: configurable; support STARTTLS and implicit TLS.
-   Default report recipient: `rohmataliwardani@gmail.com`.
-   Timezone: `Asia/Jakarta`.
-   Default operating mode: read-only.
-   No automatic malware deletion, quarantine, service restart, firewall
    modification, IP blocking, or WordPress update.

### B. Engineering rules

1.  Write maintainable, typed, modular Python code.
2.  Use clear interfaces between collectors, scanners, persistence,
    scoring, reporting, and notification modules.
3.  Use structured logging with secret redaction.
4.  Use subprocess argument arrays, strict timeouts, and safe
    environment handling.
5.  Never interpolate untrusted values into shell commands or SQL.
6.  Validate all discovered paths and prevent symlink/path traversal
    escapes.
7.  Use least privilege. Do not run WP-CLI as root.
8.  Do not expose credentials in process arguments, logs, reports,
    exceptions, or diagnostic output.
9.  Escape untrusted log/file data in HTML.
10. Implement idempotent jobs, locking, retry, deduplication, and
    graceful failure.
11. A missing dependency or unavailable check must be reported as
    `UNKNOWN` or `ERROR`, never silently treated as healthy.
12. Do not invent successful scan results or external monitoring
    configuration.
13. Avoid unnecessary dependencies. Pin dependencies and produce a lock
    file.
14. Keep high-frequency collectors lightweight and full scans
    rate-limited.
15. Do not modify existing CyberPanel, OpenLiteSpeed, MariaDB, Redis,
    SSH, or firewall configuration.

### C. Implement all required modules

Implement the modules in Part I: - Host health. - Process and service
health. - OpenLiteSpeed log and service monitoring. - MariaDB. -
Redis. - Website HTTP/DNS/SSL. - CyberPanel website discovery. -
WordPress core/plugin/theme/user audit. - WordPress checksum
verification. - SSH authentication analysis. - Firewall and Fail2Ban
audit. - Malware heuristic scan. - ClamAV integration. - Lynis
integration. - Rootkit scanner integration. - File and system
integrity. - Finding normalization, scoring, coverage, and history. -
Alert manager. - SMTP email delivery. - External heartbeat adapter. -
Weekly/monthly report generation. - SQLite retention and backup.

### D. Discovery requirements

Do not hard-code a single CyberPanel layout. Discover installation
paths, website roots, service names, log paths, PHP versions, database
socket, Redis endpoint, SSH port, and firewall implementation.

Use multiple safe discovery sources and cross-check results. Provide
explicit include/exclude configuration. Do not scan the entire
filesystem by default.

If discovery is ambiguous, show the ambiguity and require configuration
rather than guessing.

### E. Database implementation

Create versioned SQLite migrations for every required entity. Use UTC
timestamps for storage and Asia/Jakarta for display. Use parameterized
SQL, foreign keys, indexes, transactions, WAL, and safe backups.

Persist: - Metrics and rollups. - Service checks. - Website and SSL
checks. - WordPress inventory and audits. - Security findings. -
Integrity baselines/events. - Scanner runs. - Log cursors. - Alerts and
delivery attempts. - Reports and delivery attempts. - External heartbeat
state. - Administrative audit events.

Implement retention without deleting open findings or required security
evidence.

### F. Security scanner behavior

The scanner must distinguish indicators from confirmed malware. Each
finding needs severity, confidence, evidence summary, first/last seen,
fingerprint, and remediation guidance.

Do not classify a PHP file as malicious solely because it uses `eval`,
`base64_decode`, `shell_exec`, `system`, or similar functions.

Scan only configured roots, skip safe excluded paths, cap file size and
traversal depth, use bounded concurrency, and never execute scanned
files.

No automatic quarantine or deletion. Include false-positive suppression
with audit history.

A scan interrupted by timeout, permission errors, unavailable signature
database, or tool failure must be marked incomplete.

### G. External monitoring

Build a generic HTTPS heartbeat client with configurable URL and token.
Support signed payloads or bearer-token authentication. Do not send
secrets or sensitive log content.

Document how to configure an independent external monitor. Provide a
test command and explicit status showing whether the remote endpoint
accepted the heartbeat.

External monitor must be capable of detecting missing heartbeats even
when the monitored server is offline. Do not implement the only receiver
on the monitored server itself.

### H. Reporting

Generate professional, readable HTML and PDF reports.

Weekly: - Monday 07:00 Asia/Jakarta. - Previous Monday through Sunday.

Monthly: - Day 1 at 07:00 Asia/Jakarta. - Previous calendar month.

Include all sections described in Part I, with charts or compact trend
tables where useful. Reports must clearly show data coverage, missing
scans, unknown checks, and last successful check time.

Do not expose passwords, tokens, salts, full configuration files,
sensitive query strings, or raw authentication log lines.

Implement preview mode and send mode separately.

### I. CLI

Implement all commands listed in Part I. Use a standard Python CLI
framework if justified. Every command must have help, input validation,
useful exit codes, and predictable output.

Commands that send email or change a baseline require explicit flags and
confirmation. Provide `--json` output for automation where useful, while
keeping human-readable output as default.

### J. systemd and installation

Create dedicated service and timer units. Use persistent timers where
appropriate. Apply resource controls such as CPU and memory limits only
after testing compatibility. Heavy scans must use a global lock and low
I/O/CPU priority where available.

The installer must be safe, interactive, idempotent, and
non-destructive. It must back up existing SHSM configuration before
upgrade. It must not change hosting service configurations or firewall
rules.

The uninstaller must stop and disable SHSM units but preserve data by
default. Deleting data must require an explicit separate confirmation
option.

### K. Test requirements

Write unit and integration tests for: - Metrics and thresholds. - Score
and coverage. - Timezone boundaries. - Weekly/monthly period
calculations. - Log rotation and incremental cursors. - Path and symlink
security. - Secret redaction. - HTML escaping. - SQLite migrations and
backup. - Scanner incomplete/error states. - WordPress discovery and
non-root execution. - SMTP retries. - External heartbeat. - Alert
deduplication and recovery. - systemd installation. - Upgrade and
uninstall behavior.

Use fixtures and mocks; do not run destructive tests against the host
server.

### L. Development workflow

Work in this order:

1.  Inspect the target repository and existing environment. Do not
    overwrite existing user work.
2.  Create architecture and implementation checklist.
3.  Implement configuration and validation.
4.  Implement database schema and migrations.
5.  Implement core runner, logging, locks, and safe subprocess utility.
6.  Implement lightweight health collectors.
7.  Implement service, OLS, MariaDB, and Redis collectors.
8.  Implement website and SSL monitoring.
9.  Implement CyberPanel and WordPress discovery/audit.
10. Implement security checks and scanner adapters.
11. Implement findings, scoring, and alert management.
12. Implement SMTP and external heartbeat.
13. Implement weekly/monthly HTML and PDF reports.
14. Implement systemd units and lifecycle scripts.
15. Add tests and documentation.
16. Run tests, static checks, and security review.
17. Produce a final deployment checklist and sample redacted report.

Do not stop after creating skeleton files. Implement working code for
every required module. If a feature depends on unavailable external
credentials or a service not installed on the target host, implement the
adapter, report it as unconfigured, and document the exact configuration
needed.

### M. Required final handover

At completion, provide: - Project tree. - Feature implementation
matrix. - Commands to install and configure. - Required environment
variables and secret files. - systemd timer list and schedules. - SMTP
setup instructions. - External monitor setup instructions. - First-run
and verification commands. - Test results with passed/failed counts. -
Known limitations and false-positive guidance. - Backup/restore and
upgrade/uninstall procedures. - Example weekly and monthly report. -
Production deployment checklist.

The project is complete only when the application is executable, tests
pass, installation is documented, and no critical security or data-loss
issue remains unresolved.

------------------------------------------------------------------------

# PART III --- INITIAL DEPLOYMENT CHECKLIST

Before production installation:

-   [ ] Confirm Ubuntu release and security support status.
-   [ ] Confirm CyberPanel and OpenLiteSpeed paths.
-   [ ] Confirm MariaDB and Redis access methods.
-   [ ] Confirm website owner/document-root mapping.
-   [ ] Confirm SMTP sender account and app password.
-   [ ] Confirm recipient `rohmataliwardani@gmail.com`.
-   [ ] Choose an independent external monitoring provider.
-   [ ] Create external heartbeat URL and token.
-   [ ] Review scan exclusions.
-   [ ] Review CPU, RAM, disk, and alert thresholds.
-   [ ] Confirm report schedule in Asia/Jakarta.
-   [ ] Run installation in preflight/dry-run mode.
-   [ ] Review permissions and systemd units.
-   [ ] Run email and external endpoint tests.
-   [ ] Run quick scan and inspect false positives.
-   [ ] Generate weekly/monthly report previews.
-   [ ] Verify SQLite backup and restore.
-   [ ] Verify reboot recovery and missed timer handling.
-   [ ] Enable production timers only after validation.

## Final implementation principle

SHSM must prioritize **reliable detection, evidence, safe operation, and
actionable reporting** over aggressive automated remediation. It must
never claim the server is secure merely because a scan completed without
findings. Every report must disclose coverage, unavailable checks,
scanner freshness, and unresolved issues.
