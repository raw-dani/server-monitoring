# SHSM Backup & Disaster Recovery Guide

SHSM stores all collected metrics, findings, historical rollups, and audit trails in a local SQLite database (`/var/lib/shsm/monitoring.db`). This document covers safe backup, integrity validation, and restoration procedures.

---

## 1. Safe SQLite Online Backup API

**Important**: Never copy a live SQLite database file using standard `cp` while transactions may be writing in WAL (Write-Ahead Logging) mode. A raw file copy can capture inconsistent pages and result in database corruption.

SHSM uses the native SQLite Online Backup API (`sqlite3_backup_*`), which safely acquires a read-lock, checkpoints memory pages, and streams a 100% consistent copy to disk.

---

## 2. Performing a Manual Backup

```bash
shsm db backup
```
By default, backups are saved to `/var/lib/shsm/backups/monitoring_<timestamp>.db`.

To specify a custom backup destination:
```bash
shsm db backup --dest /mnt/backup-volume/shsm-backup.db
```

---

## 3. Automated Backup Schedule & Rotation

- The systemd timer `shsm-retention.timer` executes daily at 03:00.
- During retention execution, SHSM:
  1. Computes hourly and daily rollups.
  2. Purges raw metric samples older than `data_retention_days` (default 365 days).
  3. Creates an online atomic backup into `/var/lib/shsm/backups/`.
  4. Rotates old backup files, retaining the last 14 backups.

---

## 4. Integrity Validation

To test database integrity and verify that tables and indexes are free of corruption:
```bash
shsm db status
```
This runs:
- `PRAGMA quick_check`
- `PRAGMA foreign_key_check`
- Inspects database page size, WAL file presence, and latest schema version.

---

## 5. Restoration Procedure

In the event of database corruption or hardware migration:

### Step 1: Stop All SHSM Timers
Prevent background jobs from attempting writes during recovery:
```bash
sudo systemctl stop 'shsm-*.timer'
```

### Step 2: Backup Existing Files (Safety Precaution)
```bash
sudo mv /var/lib/shsm/monitoring.db /var/lib/shsm/monitoring.db.corrupt
sudo rm -f /var/lib/shsm/monitoring.db-wal /var/lib/shsm/monitoring.db-shm
```

### Step 3: Restore from Backup
```bash
sudo cp /var/lib/shsm/backups/monitoring_20261001_030000.db /var/lib/shsm/monitoring.db
sudo chown shsm:shsm /var/lib/shsm/monitoring.db
sudo chmod 0660 /var/lib/shsm/monitoring.db
```

### Step 4: Verify and Run Pending Migrations
```bash
sudo -u shsm shsm db status
sudo -u shsm shsm db migrate
```

### Step 5: Re-enable Timers
```bash
sudo systemctl start 'shsm-*.timer'
```
