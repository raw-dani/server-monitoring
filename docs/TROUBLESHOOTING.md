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

### G. Gagal Mengirim Email Alert (SMTP / Authentication Error)
- **Gejala**: Log mencatat `smtplib.SMTPAuthenticationError`, `535 Authentication failed`, atau `550 The from address does not match a verified Sender Identity`.
- **Penyebab & Solusi per Provider**:
  1. **Brevo (Sendinblue)**:
     - *Error 535*: Pastikan password yang disimpan di `/etc/shsm/secrets/smtp_password` adalah **SMTP Master Key** (awalan `xsmtpib-...`), bukan password login web dashboard biasa.
     - *Error Sender*: Pastikan `from_address` di `/etc/shsm/config.yaml` sudah terdaftar dan terverifikasi di menu *Senders & IPs* akun Brevo Anda.
  2. **Mailtrap**:
     - *Production (`provider: mailtrap`)*: Gunakan `username: "api"` dan API token resmi dari Mailtrap Email Sending, serta pastikan domain pengirim (`from_address`) sudah diverifikasi DNS-nya.
     - *Sandbox Testing (`provider: mailtrap_sandbox`)*: Gunakan username & password inbox sandbox Anda. Sandbox tidak memerlukan verifikasi domain pengirim.
  3. **SendGrid**:
     - *Error 535*: Username harus berupa string `apikey` (huruf kecil semua) dan password adalah SendGrid API Key berawalan `SG.xxx`.
     - *Error 550 Sender Identity*: Alamat `from_address` wajib terdaftar di *Single Sender Verification* atau *Domain Authentication* SendGrid.
  4. **Gmail / Google Workspace**:
     - *Error 535 5.7.8*: Gmail tidak mengizinkan password akun biasa. Wajib aktifkan *2-Step Verification* di akun Google dan buat **App Password** (Sandi Aplikasi) 16 karakter.
  5. **Local Postfix / Exim**:
     - Pastikan service lokal aktif (`systemctl status postfix` atau `systemctl status exim4`).
     - Gunakan `provider: local` (port 25 tanpa autentikasi).

- **Langkah Menyimpan Password & Pengujian**:
  1. Simpan password/API key dengan izin aman:
     ```bash
     echo "API_KEY_ATAU_PASSWORD" | sudo tee /etc/shsm/secrets/smtp_password
     sudo chown root:shsm /etc/shsm/secrets/smtp_password
     sudo chmod 0640 /etc/shsm/secrets/smtp_password
     ```
  2. Uji coba pengiriman:
     ```bash
     sudo -u shsm shsm email test
     ```

---

### H. Peringatan Penggunaan CPU Darurat (Muncul `shsm 0%` atau Pekerja `lsphp` Tinggi)
- **Gejala**: Notifikasi email: `[KRITIS] Penggunaan CPU (rata-rata 5 menit) adalah 96.8% (>= 95% ambang batas darurat). Proses teratas: shsm[3224660] 0%`.
- **Penyebab & Analisis**:
  1. **Bukan SHSM yang Menghabiskan CPU**: Angka `0%` menunjukkan SHSM sendiri sedang idle saat pengambilan sampel.
  2. **Isolasi Izin `/proc`**: SHSM berjalan sebagai user non-root `shsm`. Pada lingkungan server CyberPanel / CloudLinux / Ubuntu yang diamankan, proses pekerja PHP (`lsphp`) berjalan di bawah user Linux akun website (misalnya `atone94+`, `rejat44+`). Pada versi lama, penolakan akses saat membaca memori proses user lain menyebabkan proses tersebut terlewat dari sampling dan menyisakan proses SHSM sendiri.
  3. **Serangan Bot Scanner / Ephemeral Worker Burst**: Bot scanner yang membanjiri request 404 (seperti mencari file kredensial `/.env`, `.git`, atau brute force POST) memaksa OpenLiteSpeed memanggil script WordPress (`index.php`) berulang kali. Setiap pemanggilan WordPress memakan CPU 100%+ per worker PHP (`lsphp`).
- **Langkah Investigasi**:
  1. Periksa proses yang paling membebani CPU:
     ```bash
     ps aux --sort=-%cpu | head -n 15
     ```
  2. Periksa log akses web server untuk mendeteksi bot scanner:
     ```bash
     tail -n 100 /usr/local/lsws/logs/access.log
     ```
- **Solusi & Penanganan**:
  1. **Perbarui SHSM**:
     Terapkan pembaruan kode terbaru dan jalankan upgrade agar SHSM mendapatkan throttling `CPUQuota=40%`, prioritas `Nice=10`, serta pelaporan proses aktif yang akurat:
     ```bash
     cd /opt/shsm-src
     git pull
     sudo bash scripts/upgrade.sh
     ```
  2. **Blokir Scanner `.env` di Level Web Server (`.htaccess`)**:
     Tambahkan aturan penolakan cepat (*fast 403 Forbidden*) di file `.htaccess` website Anda (sebelum baris `# BEGIN WordPress`) agar OpenLiteSpeed langsung menolak request tanpa menyentuh PHP/WordPress:
     ```apache
     # Blokir akses ke file .env dan file konfigurasi sensitif
     <FilesMatch "^\.env|.*\.env.*$">
         Order allow,deny
         Deny from all
     </FilesMatch>

     RewriteEngine On
     RewriteRule ^.*\.env.*$ - [F,L]
     RewriteRule ^(example\.env|.*\.git|.*\.sql)$ - [F,L]
     ```
  3. **Blokir Manual IP Penyerang via Firewall (UFW / Firewalld)**:
     Jika menemukan IP agresif di log akses, buang seluruh trafik dari IP tersebut:
     - **Jika menggunakan UFW (Ubuntu Default)**:
       ```bash
       # Blokir IP langsung di urutan teratas firewall:
       sudo ufw insert 1 deny from <IP_PENYERANG> to any

       # Melihat daftar aturan UFW bernomor:
       sudo ufw status numbered

       # Membuka blokir IP jika diperlukan:
       sudo ufw delete deny from <IP_PENYERANG>
       ```
     - **Jika menggunakan Firewalld**:
       ```bash
       firewall-cmd --zone=drop --add-source=<IP_PENYERANG> --permanent
       firewall-cmd --reload

       # Melihat daftar IP yang diblokir:
       firewall-cmd --zone=drop --list-sources

       # Membuka blokir IP jika diperlukan:
       firewall-cmd --zone=drop --remove-source=<IP_PENYERANG> --permanent
       firewall-cmd --reload
       ```
  4. **Setup Auto-Ban Otomatis Menggunakan Fail2Ban (UFW / Firewalld)**:
     Agar IP yang memindai file `.env`, URL exploit, atau flooding `xmlrpc.php` otomatis diblokir oleh firewall:
     - **Buat filter Fail2Ban** di `/etc/fail2ban/filter.d/ols-scanner.conf`:
       ```ini
       [Definition]
       failregex = ^<HOST> - - \[.*\] "(GET|POST|HEAD) .*(?:\.env|\.git|\.aws|\.sql|\.bak|wp-config\.php|phpmyadmin|eval-stdin\.php).* HTTP/.*" (?:404|403) .*$
                   ^<HOST> - - \[.*\] "(GET|POST|HEAD) .*\.env.* HTTP/.*" (?:404|403) .*$
                   ^<HOST> - - \[.*\] "(GET|POST) .*(?:xmlrpc\.php).* HTTP/.*" .*$
       ignoreregex =
       ```
     - **Aktifkan jail Fail2Ban** di `/etc/fail2ban/jail.d/ols-scanner.local`:
       - **Pilihan A: Menggunakan UFW (`banaction = ufw`) [Direkomendasikan untuk Ubuntu/CyberPanel]**:
         ```ini
         [ols-scanner]
         enabled   = true
         port      = http,https
         filter    = ols-scanner
         logpath   = /usr/local/lsws/logs/access.log
         maxretry  = 3
         findtime  = 600
         bantime   = 86400
         banaction = ufw
         action    = %(action_)s
         ```
       - **Pilihan B: Menggunakan Firewalld (`banaction = firewallcmd-rich-rules`)**:
         ```ini
         [ols-scanner]
         enabled   = true
         port      = http,https
         filter    = ols-scanner
         logpath   = /usr/local/lsws/logs/access.log
         maxretry  = 3
         findtime  = 600
         bantime   = 86400
         banaction = firewallcmd-rich-rules
         action    = %(action_)s
         ```
     - **Reload Fail2Ban**:
       ```bash
       fail2ban-client reload
       ```
     - **Pantau status IP yang terkena auto-ban**:
       ```bash
       fail2ban-client status ols-scanner
       # Jika menggunakan UFW, aturan blokir otomatis terlihat di status UFW:
       sudo ufw status numbered
       ```
     - **Membuka blokir IP tertentu dari jail**:
       ```bash
       fail2ban-client set ols-scanner unbanip <IP_ADDRESS>
       ```

  5. **Auto-Ban Otomatis via SHSM (Active Defense)**:
     SHSM kini dilengkapi fitur *Active Defense* yang langsung memerintahkan Fail2Ban memblokir IP penyerang secara otomatis begitu request eksploitasi (seperti `/alfa.php` atau `php://input`) terdeteksi di log akses:
     - Fitur ini aktif secara default (`security.fail2ban_auto_block: true`).
     - Anda juga bisa memblokir atau membuka blokir IP secara langsung melalui CLI SHSM:
       ```bash
       # Blokir IP langsung ke Fail2Ban:
       sudo -u shsm shsm ban 20.194.17.163

       # Buka blokir IP:
       sudo -u shsm shsm unban 20.194.17.163
       ```

---

## 3. Pemeriksaan Log SHSM

Jika terjadi kejanggalan, pantau log utama SHSM:
```bash
# Log stream SHSM
tail -f /var/log/shsm/shsm.log

# Log journal unit systemd SHSM
journalctl -u shsm-health.service -n 50 --no-pager
journalctl -u shsm-audit-host.service -n 50 --no-pager
```
