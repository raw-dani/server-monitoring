# SHSM Operations Guide

Panduan operasional harian untuk administrator sistem menggunakan **SHSM (Server Health & Security Monitoring)**.

> [!TIP]
> Jalankan perintah CLI SHSM menggunakan user khusus non-root: `sudo -u shsm shsm <perintah>` untuk mematuhi prinsip *Least Privilege*.

---

## 1. Monitoring & Status Cepat

### Melihat Status Keseluruhan Server
Menampilkan skor kesehatan (*Health Score*), skor keamanan (*Security Score*), status subsistem, dan daftar temuan aktif (*Open Findings*):
```bash
sudo -u shsm shsm status
```
Untuk format JSON (misal untuk integrasi API / skrip eksternal):
```bash
sudo -u shsm shsm status --json
```

### Menjalankan Diagnostik Sistem (Self-Test)
Mengecek integritas SQLite database, ketersediaan binary (python3, wp, mariadb, ufw, lynis, dll), izin file rahasia, dan konfigurasi:
```bash
sudo -u shsm shsm doctor
```

---

## 2. Pengumpulan Data & Metrik (Collect)

Semua tugas pengumpulan data berjalan otomatis via timer, namun dapat dipicu secara manual sewaktu-waktu:

### Koleksi Kesehatan Host (CPU, RAM, Swap, Disk)
```bash
sudo -u shsm shsm collect health
```

### Koleksi Status Layanan Systemd (OpenLiteSpeed, MariaDB, Redis, SSH, Cron)
```bash
sudo -u shsm shsm collect services
```

### Koleksi Database (MariaDB & Redis)
Memeriksa uptime, koneksi aktif, status slow queries, buffer pool reads, dan Redis latency:
```bash
sudo -u shsm shsm collect databases
```

### Koleksi Log OpenLiteSpeed (Incremental Log Tail)
Menganalisis lonjakan error 5xx, PHP fatal error, dan pola akses:
```bash
sudo -u shsm shsm collect openlitespeed
```

---

## 3. Manajemen Website & WordPress

### Sinkronisasi & Penemuan Website
Mendeteksi domain baru dari database CyberPanel, vhost OpenLiteSpeed, dan `/home`:
```bash
sudo -u shsm shsm websites discover
```

### Audit Ketersediaan HTTP & Sertifikat SSL Website
Memeriksa resolusi DNS, waktu respon HTTP/HTTPS, dan masa aktif sertifikat SSL:
```bash
# Cek semua (HTTP + SSL)
sudo -u shsm shsm websites check

# Hanya cek masa berlaku sertifikat SSL
sudo -u shsm shsm websites check --ssl-only

# Lewati cek SSL (hanya cek DNS & HTTP status)
sudo -u shsm shsm websites check --no-ssl
```

### Penemuan & Audit WordPress
Mendeteksi instalasi WordPress serta memeriksa keamanan core, plugin, theme, dan akun administrator:
```bash
# Deteksi instalasi WordPress dan pemilik Linux-nya
sudo -u shsm shsm wordpress discover

# Jalankan audit keamanan WordPress via WP-CLI (dijalankan sebagai user pemilik situs)
sudo -u shsm shsm wordpress audit
```

---

## 4. Audit Keamanan & Pemindaian Malware

### Audit Keamanan Cepat (SSH, Firewall, Fail2Ban, Patch)
```bash
# Audit host (SSH config, active firewall, Fail2Ban jails, vulnerabilities)
sudo -u shsm shsm security audit

# Khusus audit log autentikasi SSH (brute-force detection)
sudo -u shsm shsm security audit --scope logs
```

### Pemindaian Keamanan & Malware
```bash
# Scan cepat (heuristic uploads & executable check)
sudo -u shsm shsm security scan --profile quick

# Scan mendalam (full background scan)
sudo -u shsm shsm security scan --profile full

# Menjalankan pemindai tertentu saja (opsi: heuristic, clamav, lynis, rootkit)
sudo -u shsm shsm security scan --only heuristic
sudo -u shsm shsm security scan --only clamav,rootkit
```

---

## 5. Manajemen Temuan Masalah (Findings)

Setiap masalah yang terdeteksi disimpan di database SQLite dan direkonsiliasi otomatis saat kondisi pulih. Anda juga dapat mengelolanya secara manual:

### Melihat Daftar Temuan
```bash
# Menampilkan temuan aktif yang belum selesai (OPEN)
sudo -u shsm shsm findings list

# Menampilkan temuan berdasarkan status (OPEN, ACKNOWLEDGED, RESOLVED, SUPPRESSED, ALL)
sudo -u shsm shsm findings list --status ALL

# Membatasi jumlah output
sudo -u shsm shsm findings list --limit 20
```

### Menyelesaikan / Menutup Temuan (Resolve)
```bash
# Selesaikan temuan tertentu berdasarkan UID
sudo -u shsm shsm findings resolve <UID_TEMUAN>

# Selesaikan temuan dengan catatan khusus
sudo -u shsm shsm findings resolve <UID_TEMUAN> --note "Diperbaiki oleh sysadmin"

# Selesaikan semua temuan malware sekaligus (misal pembersihan false-positive lama)
sudo -u shsm shsm findings resolve all-malware

# Selesaikan semua temuan aktif sekaligus
sudo -u shsm shsm findings resolve all
```

---

## 6. File & System Integrity Monitoring (FIM)

Memantau modifikasi tak terotorisasi pada file sistem kritis (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, dll).

### Memeriksa Status Baseline FIM
```bash
sudo -u shsm shsm integrity status
```

### Memperbarui Baseline Integritas
Jalankan ini setelah melakukan perubahan konfigurasi server yang sah (misal setelah membuat user baru atau mengubah port SSH):
```bash
sudo -u shsm shsm integrity baseline --update
```

### Memeriksa Integritas File Saat Ini terhadap Baseline
```bash
sudo -u shsm shsm integrity check
```

---

## 7. Notifikasi Email, Alert & External Heartbeat

### Menguji Pengiriman Email Notifikasi SMTP
Mengirimkan email uji coba ke daftar penerima yang dikonfigurasi:
```bash
sudo -u shsm shsm email test
```

### Menguji Alur Alert Incident
Mensimulasikan insiden kritis untuk menguji pipeline pengiriman alert:
```bash
sudo -u shsm shsm alerts test
```

### Melihat Riwayat Alert Terakhir
```bash
sudo -u shsm shsm alerts list
```

### Menguji Heartbeat Monitoring Eksternal (Uptime Kuma / Webhook)
```bash
# Uji coba pengiriman heartbeat eksternal
sudo -u shsm shsm external test

# Kirim sinyal heartbeat terjadwal
sudo -u shsm shsm external send
```

---

## 8. Laporan Berkala (Weekly & Monthly Reports)

### Membuat Laporan Mingguan
```bash
# Pratinjau lokal (membuat file HTML & PDF di /var/lib/shsm/reports/)
sudo -u shsm shsm report weekly --preview

# Buat laporan dan kirimkan via email dengan lampiran PDF
sudo -u shsm shsm report weekly --send
```

### Membuat Laporan Bulanan (Executive Summary)
```bash
# Pratinjau lokal
sudo -u shsm shsm report monthly --preview

# Buat laporan dan kirimkan via email
sudo -u shsm shsm report monthly --send
```

---

## 9. Pemeliharaan Database & Retensi Data

### Cek Integritas & Status Skema Database
```bash
sudo -u shsm shsm db status
```

### Backup Database Snapshot (Online Atomic SQLite Backup)
```bash
sudo -u shsm shsm db backup
```
*File backup tersimpan di `/var/lib/shsm/backups/monitoring_<timestamp>.db`.*

### Menjalankan Rollup & Pembersihan Data Kedaluwarsa
```bash
sudo -u shsm shsm retention run
```

---

## 10. Manajemen Service & Systemd Timers

SHSM beroperasi tanpa daemon monolitik, melainkan melalui 21 timer independen:

### Memeriksa Jadwal & Status Semua Timer SHSM
```bash
systemctl list-timers 'shsm-*'
```

### Mereset Status Unit yang Sempat Gagal (Failed)
```bash
sudo systemctl reset-failed 'shsm-*'
```

### Menjalankan Salah Satu Pekerjaan Terjadwal Secara Manual
```bash
sudo systemctl start shsm-health.service
sudo systemctl start shsm-security-audit.service
```

### Melihat Log Aktivitas Real-Time
```bash
# Log aplikasi SHSM
tail -f /var/log/shsm/shsm.log

# Log journal unit tertentu
journalctl -u shsm-health.service -n 50 --no-pager
```
