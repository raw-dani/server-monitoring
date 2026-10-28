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
  4. **Setup Auto-Ban Otomatis Menggunakan Fail2Ban (UFW / Firewalld / Iptables)**:
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
       > [!TIP]
       > Gunakan `backend = polling` agar Fail2ban tidak mengalami *stale file handle* pada log OpenLiteSpeed. Set `maxretry = 1` atau `2` karena bot scanner exploit `.env`/`.git` sering berganti IP setelah 1-2 request, dan user normal tidak akan pernah mengakses file tersebut.
       > Pastikan juga menambahkan `ignoreip` untuk melindungi IP server Anda sendiri dan IP admin dari auto-ban.

       - **Pilihan A: Menggunakan UFW (`banaction = ufw`) [Direkomendasikan untuk Ubuntu/CyberPanel]**:
         ```ini
         [ols-scanner]
         enabled   = true
         backend   = polling
         port      = http,https
         filter    = ols-scanner
         logpath   = /usr/local/lsws/logs/access.log
         maxretry  = 1
         findtime  = 600
         bantime   = 86400
         banaction = ufw
         action    = %(action_)s
         ignoreip  = 127.0.0.1/8 ::1 <IP_PUBLIK_SERVER> <IP_ADMIN>
         ```
       - **Pilihan B: Menggunakan Firewalld (`banaction = firewallcmd-rich-rules`)**:
         ```ini
         [ols-scanner]
         enabled   = true
         backend   = polling
         port      = http,https
         filter    = ols-scanner
         logpath   = /usr/local/lsws/logs/access.log
         maxretry  = 1
         findtime  = 600
         bantime   = 86400
         banaction = firewallcmd-rich-rules
         action    = %(action_)s
         ignoreip  = 127.0.0.1/8 ::1 <IP_PUBLIK_SERVER> <IP_ADMIN>
         ```
       - **Pilihan C: Menggunakan Iptables Langsung (`banaction = iptables-multiport`)**:
         ```ini
         [ols-scanner]
         enabled   = true
         backend   = polling
         port      = http,https
         filter    = ols-scanner
         logpath   = /usr/local/lsws/logs/access.log
         maxretry  = 1
         findtime  = 600
         bantime   = 86400
         banaction = iptables-multiport
         action    = %(action_)s
         ignoreip  = 127.0.0.1/8 ::1 <IP_PUBLIK_SERVER> <IP_ADMIN>
         ```
     - **Whitelist IP Server Secara Global (Opsional, Berlaku untuk Semua Jail)**:
       Tambahkan di `/etc/fail2ban/jail.local`:
       ```ini
       [DEFAULT]
       ignoreip = 127.0.0.1/8 ::1 <IP_PUBLIK_SERVER> <IP_ADMIN>
       ```
     - **Reload Fail2Ban**:
       ```bash
       fail2ban-client reload
       ```
     - **Verifikasi Whitelist IP**:
       ```bash
       fail2ban-client get ols-scanner ignoreip
       ```
     - **Pantau status IP yang terkena auto-ban**:
       ```bash
       fail2ban-client status ols-scanner
       # Jika menggunakan UFW, aturan blokir otomatis terlihat di status UFW:
       sudo ufw status numbered
       # Jika menggunakan iptables langsung:
       sudo iptables -L INPUT -n -v | grep f2b
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

### I. Website atau WordPress Tidak Ditemukan (`Discovered 0 active website(s)` / `0 WordPress site(s)`)
- **Gejala**:
  - `sudo -u shsm shsm websites discover` menghasilkan `Discovered 0 active website(s) (0 newly added, 0 removed)`.
  - `sudo -u shsm shsm wordpress discover` menghasilkan `Discovered 0 WordPress site(s)`.
  - Pada tampilan `shsm status`, baris `Websites Monitored: 0`.

- **Penyebab**:
  1. **CyberPanel Menyimpan Data Website di MariaDB (Bukan SQLite)**:
     CyberPanel menyimpan konfigurasi domain di database MariaDB `cyberpanel` pada tabel `websiteFunctions_websites` (`domain`, `adminEmail`, `externalApp`, `path`). File SQLite `/etc/cyberpanel/cyberpanel.db` tidak ada pada instalasi standar CyberPanel.
  2. **Izin Direktori `/home/<domain>` Terbatas (Group `nobody`)**:
     Di CyberPanel, direktori website (misalnya `/home/domain.com/public_html`) memiliki kepemilikan `user:nobody` dengan izin `0750` (`rwxr-x---`). Jika user sistem `shsm` belum dimasukkan ke group `nobody` atau `nogroup`, pembacaan folder ditolak (`PermissionError: [Errno 13] Permission denied`).
  3. **Loop Scanner `/home` Terhenti oleh Exception Folder Terisolasi**:
     Jika di dalam `/home` terdapat folder khusus milik root/sistem dengan izin terbatas (seperti `/home/cyberpanel` atau `/home/docker` mode `0700`), iterasi scanner versi lama langsung terhenti saat menemui exception, sehingga membatalkan pemindaian sisa website lainnya.
  4. **Ketergantungan WordPress Discovery terhadap Inventory Website**:
     Perintah `shsm wordpress discover` mencari instalasi WordPress di dalam daftar website aktif yang tersimpan di inventory SHSM. Jika `websites discover` belum berhasil menemukan website, maka `wordpress discover` tidak memiliki direktori untuk dipindai.

- **Solusi & Langkah Penanganan**:
  1. **Tambahkan User `shsm` ke Group `nobody` & `nogroup`**:
     ```bash
     sudo usermod -aG nobody,nogroup shsm
     ```
  2. **Perbarui Codebase & Jalankan Upgrade Script**:
     Pembaruan ini menyertakan fitur query otomatis ke database MariaDB `cyberpanel`, pembacaan virtualhost dari `/usr/local/lsws/conf/httpd_config.conf`, serta penanganan exception yang aman per direktori:
     ```bash
     cd /opt/shsm-src
     git pull
     sudo bash scripts/upgrade.sh
     ```
  3. **Jalankan Ulang Discovery Website**:
     ```bash
     sudo -u shsm shsm websites discover
     ```
     *Output akan menampilkan seluruh domain aktif yang ditemukan berserta direktori root-nya.*
  4. **Jalankan Ulang Discovery WordPress**:
     ```bash
     sudo -u shsm shsm wordpress discover
     ```
     *Output akan menampilkan versi WordPress dan pemilik Linux untuk setiap website.*
  5. **Verifikasi Status Monitoring**:
     ```bash
     sudo -u shsm shsm status
     ```

---

### J. Lonjakan CPU 100% Akibat Request Masif ke `index.php` dan `xmlrpc.php` (Botnet 404/L7 Flood)

- **Gejala**:
  - Di `htop`, seluruh core CPU mencapai 100% dengan `Load average` melonjak drastis (di atas 20-30).
  - Terdapat puluhan proses `lsphp: .../public_html/index.php` dan `.../xmlrpc.php` berjalan bersamaan di banyak domain.
  - Proses `mysqld` memakan CPU tinggi (40–80%) karena setiap request WordPress memicu kueri database.
  - Di log OpenLiteSpeed (`tail -f /usr/local/lsws/logs/access.log`), terlihat ribuan request `POST` beruntun ke URL non-existent seperti `/app`, `/api/route`, `/login`, `/dashboard`, `/admin` dengan status HTTP `404` dan menggunakan User-Agent bot palsu (`Baiduspider`, `DeepSeekBot`, `Googlebot`, `ChatGPT-User`, dll).

- **Akar Masalah**:
  1. **WordPress 404 Handling Menguras CPU**:
     Di WordPress, setiap request ke URL yang tidak ada (404) diarahkan oleh OpenLiteSpeed ke `index.php`. WordPress harus memuat core, plugin, dan mengeksekusi kueri database MySQL hanya untuk merender halaman 404. Ribuan request per detik langsung melumpuhkan CPU.
  2. **Botnet Cloud Provider (IP Spoofing / Scraping)**:
     Penyerang menggunakan jaringan IP cloud (seperti Google Cloud `34.x.x.x` dan `35.x.x.x`) untuk menembakkan request POST liar secara masif.
  3. **Eksploitasi `xmlrpc.php`**:
     Bot mencoba melakukan XML-RPC pingback amplification atau brute-force credentials.

- **Solusi & Langkah Penanganan**:
  1. **Jalankan Auto-Blocker SHSM**:
     SHSM secara otomatis mendeteksi IP yang menghasilkan > 50 request 404 dalam satu siklus dan mengeksekusi `iptables -I INPUT -s <IP> -j DROP`:
     ```bash
     sudo -u shsm shsm collect openlitespeed
     ```
  2. **Verifikasi Daftar Blokir iptables**:
     Periksa apakah IP penyerang sudah masuk target `DROP`:
     ```bash
     sudo iptables -L INPUT -n -v | grep DROP
     ```
     > [!IMPORTANT]
     > Jika IP publik server Anda sendiri ikut terblokir (karena request internal), segera unblock:
     > ```bash
     > sudo iptables -D INPUT -s <IP_PUBLIK_SERVER> -j DROP
     > ```
     > Dan pastikan IP tersebut didaftarkan pada `ip_whitelist` di `/etc/shsm/config.yaml`.

  3. **Cara Blokir Otomatis IP 404 Terbanyak Menggunakan SHSM**:
     SHSM memiliki fitur pemindaian log akses dan auto-drop iptables terpusat:
     ```bash
     # Mode simulasi (melihat IP mana saja yang akan diblokir tanpa mengeksekusi):
     sudo -u shsm shsm block-scanners --threshold 30 --dry-run

     # Eksekusi blokir instan via iptables DROP untuk semua IP luar dengan 404 >= 30:
     sudo -u shsm shsm block-scanners --threshold 30
     ```
     *SHSM secara cerdas mengecualikan IP server Anda sendiri dan loopback (`127.0.0.1`), sehingga aman dijalankan.*

     Atau jika ingin mengecek status manual perbandingan dengan iptables:
     ```bash
     grep " 404 " /usr/local/lsws/logs/access.log | awk '{print $1}' | sort | uniq -c | sort -nr | head -n 20
     ```

  4. **Matikan `xmlrpc.php` di Seluruh Domain**:
     Serangan XML-RPC Pingback/Brute-force memicu eksekusi database MySQL yang sangat berat (`mysqld` 90%+). Matikan total dengan dua lapis perlindungan:

     **A. Blokir Global di OpenLiteSpeed (Paling Efisien - Zero PHP Execution)**:
     Tambahkan aturan rewrite global di `/usr/local/lsws/conf/httpd_config.conf` agar server langsung membalas `403 Forbidden` di pintu gerbang:
     ```text
     rewrite  {
       enable                  1
       autoLoadHtaccess        1
       rules                   <<<END_rules
       RewriteCond %{REQUEST_URI} ^/.*xmlrpc\.php$ [NC]
       RewriteRule .* - [F,L]
       END_rules
     }
     ```

     **B. Blokir Lapis Kedua via `.htaccess` Semua Website**:
     Sisipkan rule blokir di baris pertama seluruh file `.htaccess`:
     ```bash
     for f in /home/*/public_html/.htaccess; do
         if [ -f "$f" ]; then
             sed -i '1s/^/<Files xmlrpc.php>\nOrder Deny,Allow\nDeny from all\n<\/Files>\n\n/' "$f"
             echo "Locked XML-RPC on $f"
         fi
     done
     ```

  5. **Tolak Request POST Liar Sebelum Menyentuh PHP**:
     Tambahkan rule RewriteCond di `.htaccess` untuk me-reject (HTTP 403 Forbidden) request POST ke endpoint non-existent tanpa meneruskannya ke `index.php`:
     ```apache
     RewriteEngine On
     RewriteCond %{REQUEST_METHOD} POST
     RewriteCond %{REQUEST_URI} ^/(app|api|actions|login|admin|dashboard|settings) [NC]
     RewriteRule .* - [F,L]
     ```

  6. **Bunuh Proses PHP yang Menggantung & Restart Web Server**:
     Setelah proteksi XML-RPC dan POST terpasang, bersihkan seluruh proses PHP yang masih menggantung:
     ```bash
     killall -9 lsphp
     /usr/local/lsws/bin/lswsctrl restart
     ```
     *Setelah restart, proses `xmlrpc.php` akan hilang total dari `htop`, beban `mysqld` akan anjlok kembali ke < 5%, dan load average server akan normal.*

---

## 3. Pemeriksaan Log SHSM

Jika terjadi kejanggalan, pantau log utama SHSM:
```bash
# Log stream SHSM
tail -f /var/log/shsm/shsm.log

# Log journal unit systemd SHSM
journalctl -u shsm-health.service -n 50 --no-pager
journalctl -u shsm-audit-host.service -n 50 --no-pager
journalctl -u shsm-openlitespeed.service -n 50 --no-pager
journalctl -u shsm-ddos.service -n 50 --no-pager
```

