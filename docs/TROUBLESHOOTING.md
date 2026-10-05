# SHSM Troubleshooting Guide

This guide describes common diagnostic scenarios, symptom explanations, and verified resolutions.

---

## 1. Quick Diagnostic: Run Doctor
Always start by running:
```bash
shsm doctor
```
`shsm doctor` executes 12 system validation routines, checks permissions, tests external binaries, and prints clear error recommendations.

---

## 2. Common Issues & Solutions

### A. Permission Denied on SQLite Database (`/var/lib/shsm/monitoring.db`)
- **Symptom**: `sqlite3.OperationalError: unable to open database file` or `permission denied`.
- **Cause**: Database file or directory ownership belongs to root instead of `shsm`.
- **Resolution**:
  ```bash
  sudo chown -R shsm:shsm /var/lib/shsm /var/log/shsm
  sudo chmod 0750 /var/lib/shsm /var/log/shsm
  sudo chmod 0660 /var/lib/shsm/monitoring.db*
  ```

### B. WordPress Check Reports "WP-CLI is not installed or not in PATH"
- **Symptom**: `shsm wordpress audit` reports `CheckStatus.ERROR` or `wp-cli binary not found`.
- **Cause**: WP-CLI is installed in a directory not included in the standard system PATH.
- **Resolution**:
  1. Verify where WP-CLI binary exists:
     ```bash
     which wp || command -v wp
     ```
  2. If missing, install WP-CLI globally:
     ```bash
     curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
     chmod +x wp-cli.phar
     sudo mv wp-cli.phar /usr/local/bin/wp
     ```
  3. Ensure `/etc/sudoers.d/shsm` allows user `shsm` to execute `/usr/local/bin/wp`.

### C. SMTP Authentication Failed
- **Symptom**: Email alerts or weekly reports log `smtplib.SMTPAuthenticationError`.
- **Cause**: Incorrect username/password, or Gmail App Password required.
- **Resolution**:
  1. For Gmail SMTP, enable 2-Step Verification on the Google Account and generate a 16-character **App Password**.
  2. Store the App Password into `/etc/shsm/secrets/smtp_password`:
     ```bash
     echo "your-16-char-app-password" | sudo tee /etc/shsm/secrets/smtp_password
     sudo chmod 0600 /etc/shsm/secrets/smtp_password
     sudo chown shsm:shsm /etc/shsm/secrets/smtp_password
     ```
  3. Test delivery:
     ```bash
     shsm alert test
     ```

### D. Security Audit Notes: ClamAV / Lynis Unavailable
- **Symptom**: Findings or checks report `clamscan not found` or `lynis not found`.
- **Explanation**: These tools are optional. SHSM gracefully handles their absence and records `CheckStatus.NOT_APPLICABLE` or `UNKNOWN` without failing scans.
- **Resolution**:
  If you wish to enable them:
  ```bash
  sudo apt-get update
  sudo apt-get install -y clamav clamav-daemon lynis rkhunter chkrootkit
  sudo freshclam
  ```

### E. Service Flapping Detected
- **Symptom**: SHSM emits a finding: `Service <name> is flapping (X restarts in 10 minutes)`.
- **Cause**: The systemd service crashed and restarted multiple times within the flapping window.
- **Investigation**:
  Check journal logs for the specific service:
  ```bash
  journalctl -u lshttpd.service -n 100 --no-pager
  ```

---

## 3. Log Inspection

SHSM logs all background activity, errors, and scan durations to:
```bash
tail -f /var/log/shsm/shsm.log
```
Or view the systemd journal for any specific timer or service:
```bash
journalctl -u shsm-health.service -e
```
