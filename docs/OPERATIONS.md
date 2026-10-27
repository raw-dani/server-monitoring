# SHSM Operations Guide

Panduan operasional harian untuk administrator sistem menggunakan **SHSM (Server Health & Security Monitoring)**.

> [!TIP]
> **Shorthand Execution**: Anda dapat langsung menjalankan perintah cukup dengan `shsm <perintah>` (misal `shsm status`, `shsm blocked`).
> Wrapper bawaan SHSM di `/usr/local/bin/shsm` secara otomatis mendeteksi dan menurunkan hak akses (*drop privileges*) ke user `shsm` di belakang layar agar integritas izin file database tetap terjaga. Anda juga tetap dapat memanggil via `sudo -u shsm shsm <perintah>`.

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

### Koleksi Antrean Email & Deteksi Outbound Spam Bot
Memantau antrean Postfix queue spools dan mendeteksi script non-MTA (PHP/shell) yang mencoba koneksi langsung ke port SMTP keluar (port 25, 465, 587):
```bash
sudo -u shsm shsm collect mail
```

### Koleksi Anomali Soket DDoS & Koneksi Konkuren Web
Memeriksa TCP SYN flood (`SYN_RECV`) dan mendeteksi IP tunggal yang membuka koneksi simultan berlebih pada port 80/443:
```bash
sudo -u shsm shsm collect ddos
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

### Manajemen Blokir IP Terpusat (Fail2Ban + iptables)
SHSM menyediakan manajemen terpusat untuk memantau, memeriksa, memblokir, dan membuka blokir IP baik yang berada di Fail2Ban maupun di iptables:
```bash
# 1. Melihat semua IP & subnet yang sedang diblokir (dari Fail2Ban dan iptables):
sudo -u shsm shsm blocked

# 2. Memeriksa apakah IP tertentu sedang diblokir (termasuk deteksi jika terkena blokir subnet CIDR):
sudo -u shsm shsm blocked <IP_ADDRESS>

# 3. Blokir IP penyerang:
# Default: Dikirim ke Fail2Ban (dengan fallback otomatis ke iptables jika Fail2Ban tidak aktif)
sudo -u shsm shsm ban <IP_ADDRESS>
# Tentukan jail tertentu:
sudo -u shsm shsm ban <IP_ADDRESS> --jail ols-scanner
# Atau blokir langsung di iptables (DROP rule):
sudo -u shsm shsm ban <IP_ADDRESS> --iptables

# 4. Buka blokir IP terpusat (otomatis membersihkan dari Fail2Ban DAN iptables sekaligus):
sudo -u shsm shsm unban <IP_ADDRESS>
```

### Audit Reputasi IP Server pada DNSBL / RBL (Anti-Spam Blacklist)
Memeriksa status IP publik server terhadap database DNSBL ternama (Spamhaus, Barracuda, SpamCop, SORBS, PSBL, Mailspike) untuk deteksi dini pemblokiran IP akibat spam malware:
```bash
sudo -u shsm shsm security rbl
```

### Audit Konfigurasi Anti-DDoS & Bot Throttling OpenLiteSpeed
Memeriksa apakah batas koneksi per klien (`perClientConnLimit`), masa ban (`banPeriod`), serta challenge anti-DDoS / reCAPTCHA telah aktif di OpenLiteSpeed:
```bash
sudo -u shsm shsm security ols-ddos
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

Memantau modifikasi file sistem kritis (`/etc/passwd`, `/etc/group`, `/etc/sudoers`, `/etc/ssh/sshd_config`, dll) dengan **Smart Account & Group Diffing**:
- **[INFO] System Accounts**: Penambahan akun paket/layanan resmi (UID < 1000 dengan non-login shell `/bin/false` atau `/usr/sbin/nologin` seperti `clamav`, `shsm`, `redis`) diklasifikasikan sebagai `INFO` disertai bukti log installer (`auth.log`), tanpa memicu kepanikan atau penalti skor.
- **[WARNING] New Interactive Users**: Akun login baru (UID >= 1000 dengan shell `/bin/bash` atau `/bin/sh`) diklasifikasikan sebagai `MEDIUM/WARNING` untuk verifikasi admin.
- **[CRITICAL] Backdoor & Privilege Escalation**: Akun UID 0 selain root, perubahan shell service account menjadi `/bin/bash`, atau penambahan user ke grup istimewa (`sudo`, `wheel`, `docker`) langsung memicu alarm `CRITICAL`.

### Memeriksa Status Baseline FIM
```bash
sudo -u shsm shsm integrity status
```

### Memeriksa Integritas File Saat Ini terhadap Baseline
```bash
sudo -u shsm shsm integrity check
```

### Memperbarui Baseline Integritas
Jalankan ini setelah melakukan perubahan konfigurasi server yang sah (misal setelah menginstal paket baru, membuat user resmi, atau mengubah port SSH) untuk memperbarui baseline dan otomatis menyelesaikan (*auto-resolve*) alert:
```bash
sudo -u shsm shsm integrity baseline --update
```


---

## 7. Notifikasi Email, Alert & External Heartbeat

### Mengonfigurasi & Mengganti Provider Email
SHSM mendukung preset email siap pakai (`brevo`, `mailtrap`, `mailtrap_sandbox`, `sendgrid`, `mailgun`, `postmark`, `gmail`, `local`, `custom`).

1. Buka konfigurasi:
   ```bash
   sudo nano /etc/shsm/config.yaml
   ```
2. Sesuaikan blok `email:` (misalnya Brevo, Mailtrap, atau SendGrid):
   ```yaml
   email:
     enabled: true
     provider: brevo
     username: "akun-anda@example.com"
     from_address: "alerts@domain-anda.com"
     recipients:
       - "rohmataliwardani@gmail.com"
   ```
3. Simpan password atau API key penyedia email Anda:
   ```bash
   echo "API_KEY_ATAU_PASSWORD" | sudo tee /etc/shsm/secrets/smtp_password
   sudo chown root:shsm /etc/shsm/secrets/smtp_password
   sudo chmod 0640 /etc/shsm/secrets/smtp_password
   ```

### Menguji Pengiriman Email Notifikasi SMTP
Mengirimkan email uji coba ke daftar penerima yang dikonfigurasi untuk memverifikasi koneksi dan kredensial:
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

SHSM beroperasi tanpa daemon monolitik, melainkan melalui 24 systemd timer independen yang efisien:

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
# Menjalankan pemantauan socket flood & DDoS
sudo systemctl start shsm-ddos.service

# Menjalankan audit antrean mail & koneksi outbound SMTP
sudo systemctl start shsm-mail.service

# Menjalankan audit reputasi RBL IP publik
sudo systemctl start shsm-security-rbl.service

# Menjalankan health & host security audit
sudo systemctl start shsm-health.service
sudo systemctl start shsm-audit-host.service
```

### Melihat Log Aktivitas Real-Time
```bash
# Log aplikasi SHSM
tail -f /var/log/shsm/shsm.log

# Log journal unit tertentu
journalctl -u shsm-ddos.service -n 50 --no-pager
journalctl -u shsm-mail.service -n 50 --no-pager
journalctl -u shsm-health.service -n 50 --no-pager
```

