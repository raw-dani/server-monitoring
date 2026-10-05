# SHSM Troubleshooting Guide

Panduan diagnostik cepat, penjelasan gejala masalah (*symptoms*), dan langkah penyelesaian (*resolutions*) untuk SHSM.

---

## 1. Langkah Pertama: Jalankan SHSM Doctor

Selalu mulai investigasi masalah dengan perintah diagnostik mandiri:
```bash
sudo -u shsm shsm doctor
```
`shsm doctor` memvalidasi 12 komponen sistem:
- Sintaks dan nilai konfigurasi YAML.
- Izin file rahasia (`/etc/shsm/secrets/`).
- Integritas database SQLite (`PRAGMA quick_check` & WAL mode).
- Ketersediaan binary penting (`systemctl`, `mariadb`, `mysql`, `wp`, `ufw`, `fail2ban-client`, dll).

---

## 2. Masalah Umum & Solusinya

### A. Permission Denied pada File Lock (`/run/shsm/*.lock`)
- **Gejala**: `PermissionError: [Errno 13] Permission denied: '/run/shsm/audit-host.lock'`.
- **Penyebab**: Direktori `/run/` bertipe `tmpfs` milik `root:root`. Pada reboot atau instalasi tertentu, direktori `/run/shsm` belum dibuat atau belum dimiliki oleh user `shsm`.
- **Solusi**:
  1. Default lock path di versi terbaru telah dipindahkan ke `/var/lib/shsm/locks` yang selalu dimiliki oleh `shsm:shsm`.
  2. Pastikan izin direktori benar:
     ```bash
     sudo mkdir -p /var/lib/shsm/locks /run/shsm
     sudo chown -R shsm:shsm /var/lib/shsm/locks /run/shsm
     sudo chmod 0750 /var/lib/shsm/locks
     sudo chmod 0775 /run/shsm
     ```
  3. Konfigurasi `systemd-tmpfiles` otomatis dibuat di `/etc/tmpfiles.d/shsm.conf` agar `/run/shsm` tetap dibuat dengan izin `0775 shsm shsm` saat server reboot.

---

### B. MariaDB Dilaporkan "Down or Inaccessible" pada CyberPanel
- **Gejala**: `[CRITICAL] MariaDB database is down or inaccessible` padahal service `mariadb` aktif.
- **Penyebab**: Di CyberPanel, password root MySQL disimpan dalam format plain text di `/etc/cyberpanel/mysqlPassword`, sedangkan konfigurasi default membaca `/etc/mysql/debian.cnf` yang hanya bisa dibaca oleh root.
- **Solusi**:
  1. Jalankan ulang script instalasi untuk mengenerate `/etc/shsm/secrets/my.cnf` secara otomatis:
     ```bash
     sudo bash scripts/install.sh
     ```
  2. Atau buat manual file `/etc/shsm/secrets/my.cnf`:
     ```ini
     [client]
     user=root
     password=<password_dari_/etc/cyberpanel/mysqlPassword>
     socket=/var/run/mysqld/mysqld.sock
     ```
  3. Berikan hak akses aman:
     ```bash
     sudo chown root:shsm /etc/shsm/secrets/my.cnf
     sudo chmod 0640 /etc/shsm/secrets/my.cnf
     ```
  4. Jalankan pengumpulan database untuk memperbarui status:
     ```bash
     sudo -u shsm shsm collect databases
     ```

---

### C. Port 21 Dilaporkan sebagai "MariaDB Database Port Publicly Exposed"
- **Gejala**: `[CRITICAL] MariaDB database port 21 is publicly exposed (Asset: MariaDB:21)`.
- **Penyebab**: Daemon FTP CyberPanel (`pure-ftpd-mysql`) memiliki kata `mysql` pada nama prosesnya. Versi lama salah mengenali semua proses berunsur "mysql" sebagai database.
- **Solusi**:
  1. Lakukan `git pull origin main && sudo bash scripts/install.sh`.
  2. Jalankan ulang audit keamanan untuk mengoreksi dan menyelesaikan temuan:
     ```bash
     sudo -u shsm shsm security audit
     ```

---

### D. Muncul Banyak Temuan Palsu Malware pada File WordPress Core di `/tmp/`
- **Gejala**: Muncul ratusan temuan `[HIGH] Executable PHP file located in uploads/temp directory: wp-signup.php`.
- **Penyebab**: Heuristik lama memperlakukan file PHP apa pun di `/tmp/` seolah-olah file yang diupload ke folder media.
- **Solusi**:
  1. Bersihkan temuan palsu lama dari database:
     ```bash
     sudo -u shsm shsm findings resolve all-malware
     ```
  2. Jalankan ulang pemindaian:
     ```bash
     sudo -u shsm shsm security scan --profile quick
     ```

---

### E. Muncul Unit Systemd Berstatus Failed (`cloud-config`, `cloud-init`, dll)
- **Gejala**: `[HIGH] failed systemd unit(s) detected`.
- **Penyebab**: Beberapa service oneshot bawaan cloud VPS (seperti `cloud-init`, `networkd-dispatcher`, atau `shsm-*.service` dari instalasi pertama) gagal dan statusnya tersimpan di memori systemd.
- **Solusi**:
  1. Periksa unit yang gagal:
     ```bash
     systemctl --failed
     ```
  2. Bersihkan/reset status kegagalan unit yang sudah tidak aktif:
     ```bash
     sudo systemctl reset-failed
     ```
  3. Perbarui status di SHSM:
     ```bash
     sudo -u shsm shsm collect services
     ```

---

### F. Gagal Membuat User: `useradd: cannot open /etc/passwd`
- **Gejala**: Pesan kesalahan `useradd: cannot open /etc/passwd` saat menjalankan `install.sh`.
- **Penyebab**: File autentikasi sistem dikunci dengan atribut Linux immutable (`+i`) atau append-only (`+a`).
- **Solusi**:
  1. Lepaskan atribut pengunci sebelum instalasi:
     ```bash
     sudo chattr -ia /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null || true
     ```
  2. Jalankan kembali:
     ```bash
     sudo bash scripts/install.sh
     ```

---

### G. Gagal Mengirim Email Alert (SMTP Authentication Error)
- **Gejala**: Log mencatat `smtplib.SMTPAuthenticationError`.
- **Penyebab**: Password akun email salah atau akun Gmail memerlukan **App Password** (Sandi Aplikasi).
- **Solusi**:
  1. Untuk Gmail / Google Workspace, aktifkan 2-Step Verification dan buat **App Password** 16 karakter.
  2. Simpan sandi ke `/etc/shsm/secrets/smtp_password`:
     ```bash
     echo "your-16-char-app-password" | sudo tee /etc/shsm/secrets/smtp_password
     sudo chown root:shsm /etc/shsm/secrets/smtp_password
     sudo chmod 0640 /etc/shsm/secrets/smtp_password
     ```
  3. Uji pengiriman email:
     ```bash
     sudo -u shsm shsm email test
     ```

---

## 3. Pemeriksaan Log SHSM

Jika terjadi kejanggalan, pantau log utama SHSM:
```bash
# Log stream SHSM
tail -f /var/log/shsm/shsm.log

# Log journal unit systemd SHSM
journalctl -u shsm-health.service -n 50 --no-pager
journalctl -u shsm-security-audit.service -n 50 --no-pager
```
