# SHSM Operations Guide

This guide provides day-to-day operational procedures for administrators using SHSM.

---

## 1. Daily & Routine Operations

### Checking System Health & Scores
To quickly inspect current server health, security posture, active findings, and monitored websites:
```bash
shsm status
```
For programmatic consumption (JSON output):
```bash
shsm status --json
```

### Running Comprehensive Diagnostics
When investigating anomalies or testing system readiness:
```bash
shsm doctor
```
Checks:
- System binaries (python3, wp, lynis, clamscan, ufw, fail2ban)
- File permissions on `/var/lib/shsm`, `/etc/shsm/secrets`
- SQLite WAL mode and integrity check (`PRAGMA quick_check`)
- Active systemd timer statuses

---

## 2. Manual Scans & Audits

### Triggering a Health Collection
To collect CPU, memory, disk, service states, database metrics, and web response latencies:
```bash
shsm health run
```
Options:
- `--dry-run`: Evaluate collectors without persisting metrics or updating findings in SQLite.

### Triggering a Quick Security Audit
To scan SSH logs, firewall status, fail2ban jails, and recent uploads:
```bash
shsm security audit
```

### Triggering a Full Deep Security Scan
To run deep ClamAV malware scans, rootkit checks (rkhunter/chkrootkit), and file integrity verification:
```bash
shsm security scan-full
```

---

## 3. Managing Findings & Incidents

### Viewing Active Findings
```bash
shsm findings list --status OPEN
```

### Finding Details & Evidence
```bash
shsm findings show <FINDING_ID>
```

### Deduplication and Auto-Reconciliation
Findings in SHSM are uniquely identified by a SHA-256 fingerprint computed from `(check_id, asset, key)`.
- When an issue persists across multiple scans, SHSM updates the `last_seen` timestamp and increments `occurrences` without creating duplicate alert emails.
- When a subsequent scan conclusively verifies that the issue has been resolved (e.g. disk usage drops below threshold, or modified WP core file is replaced), SHSM automatically marks the finding as `RESOLVED` and dispatches a Recovery notification (if enabled).

---

## 4. Reports & Manual Delivery

### Generating Weekly Report
```bash
shsm report weekly --send
```
This generates:
- An HTML report summary formatted for modern email clients.
- A high-resolution PDF report built natively via ReportLab and attached to the email.
- The generated PDF is archived at `/var/lib/shsm/reports/weekly_<timestamp>.pdf`.

### Generating Monthly Executive Report
```bash
shsm report monthly --send
```

---

## 5. Systemd Timer Management

SHSM uses 21 individual systemd timers rather than a monolithic daemon.

### Inspecting All Timers
```bash
shsm schedule status
# or
systemctl list-timers 'shsm-*'
```

### Manually Triggering a Scheduled Job
```bash
sudo systemctl start shsm-health.service
```

### Viewing Logs for a Scheduled Job
```bash
journalctl -u shsm-health.service -n 50 --no-pager
```
