# Panduan Arsitektur & Implementasi Proteksi DDoS Cerdas (Adaptive Anti-DDoS)

Dokumen ini mendokumentasikan strategi pertahanan **Multi-Layer Adaptive Anti-DDoS** untuk server produksi yang menjalankan **CyberPanel**, **OpenLiteSpeed (OLS)**, **CSF (ConfigServer Security & Firewall)**, **MariaDB**, dan **WordPress**.

---

## 1. Konsep Utama: Multi-Layer Defense

Tujuan proteksi cerdas adalah **menahan serangan di level serendah mungkin** sebelum menyentuh aplikasi dinamis (PHP & MariaDB), sehingga pengunjung manusia asli tetap dapat mengakses situs secara normal sementara bot penyerang dibekukan tanpa membebani CPU.

```
                      [ Serangan Botnet / HTTP Flood ]
                                     │
                                     ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │ Layer 1: Edge Cloudflare WAF                                          │
 │ - Bot Fight Mode & Managed Challenge pada wp-login.php/xmlrpc.php     │
 │ - Menyaring ~70% trafik kotor sebelum menyentuh IP Publik server      │
 └───────────────────────────────────┬───────────────────────────────────┘
                                     │
                                     ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │ Layer 2: CSF / Kernel IPTables (Layer 4 TCP)                          │
 │ - PORTFLOOD: Batasi max 40 koneksi baru per 5 detik                   │
 │ - CT_LIMIT: Batasi max 80 koneksi simultan per IP (Slowloris/SYN)     │
 └───────────────────────────────────┬───────────────────────────────────┘
                                     │
                                     ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │ Layer 3: OpenLiteSpeed Adaptive Throttling (Layer 7 HTTP)             │
 │ - dynReqPerSec: Batasi max 5 dynamic request/detik per client         │
 │ - reCaptcha / JS Bot Challenge transparan untuk browser asli          │
 └───────────────────────────────────┬───────────────────────────────────┘
                                     │
                                     ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │ Layer 4: LiteSpeed HTML Cache (LSCache)                               │
 │ - Halaman artikel disajikan langsung dari RAM (< 0.005s)              │
 │ - PHP (lsphp) dan Database (mysqld) 0% CPU footprint                  │
 └───────────────────────────────────────────────────────────────────────┘
```

---

## 2. Implementasi Layer 1: Cloudflare Edge Rules

Jika domain diproxy melalui Cloudflare:
1. **Managed Challenge untuk Area Rawan**:
   - Menu: **Security** -> **WAF** -> **Custom Rules** -> Create Rule.
   - Field: `(http.request.uri.path contains "wp-login.php") or (http.request.uri.path contains "xmlrpc.php")`
   - Action: **Managed Challenge**.
2. **Aktifkan Bot Fight Mode**:
   - Menu: **Security** -> **Bots** -> Aktifkan **Bot Fight Mode**.

---

## 3. Implementasi Layer 2: CSF Connection Tracking & Port Flood

Buka konfigurasi CSF di `/etc/csf/csf.conf`:
```bash
nano /etc/csf/csf.conf
```

Sesuaikan parameter berikut:

### A. Port Flood Protection (`PORTFLOOD`)
Membatasi pembuatan socket TCP baru secara agresif:
```ini
# Port 80 & 443: Maksimal 40 koneksi per 5 detik
# Port SSH 22891: Maksimal 5 koneksi per 300 detik
PORTFLOOD = "80;tcp;40;5,443;tcp;40;5,22891;tcp;5;300"
```

### B. Connection Tracking (`CT_LIMIT`)
Mendeteksi serangan Slowloris atau banjir socket gantung:
```ini
CT_LIMIT = "80"
CT_INTERVAL = "30"
CT_BLOCK_TIME = "1800"
CT_PERMANENT = "0"
```

Setelah konfigurasi disimpan, muat ulang firewall:
```bash
csf -r
```

---

## 4. Implementasi Layer 3: OpenLiteSpeed Adaptive Throttling & Bot Challenge

Edit file `/usr/local/lsws/conf/httpd_config.conf`:

### A. Pembatasan Request Dinamis per Client
Membatasi eksekusi PHP hanya maksimal 5 req/detik per IP. Jika melanggar, IP dibekukan selama 180 detik di level web server:
```text
perClientConnLimit  {
  staticReqPerSec         30
  dynReqPerSec            5
  outBandwidth            0
  inBandwidth             0
  softLimit               60
  hardLimit               100
  blockBadReq             1
  gracePeriod             10
  banPeriod               180
}
```

### B. Anti-DDoS reCaptcha / JavaScript Challenge
Menguji pengunjung saat beban server naik (browser manusiawi akan lolos otomatis tanpa popup, sedangkan skrip otomatis/curl akan ter-drop):
```text
reCaptcha  {
  enabled                 1
  type                    2
  maxConns                30
  difficulty              5
}
```

---

## 5. Implementasi Layer 4: LiteSpeed Cache (Zero PHP/SQL Footprint)

Pastikan modul cache pada `.htaccess` setiap website aktif:
```apache
# BEGIN LiteSpeed Cache
<IfModule Litespeed>
CacheLookup on
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^HEAD|GET$
RewriteCond %{HTTP_COOKIE} !wp-postpass_ [NC]
RewriteCond %{HTTP_COOKIE} !comment_author_ [NC]
RewriteCond %{HTTP_COOKIE} !wordpress_logged_in_ [NC]
RewriteCond %{REQUEST_URI} !/(wp-admin|wp-login.php|xmlrpc.php) [NC]
RewriteRule .* - [E=Cache-Control:max-age=1800]
</IfModule>
# END LiteSpeed Cache
```

---

## 6. Integrasi Otomatis SHSM Scanner Blocker

Agar IP yang memicu error 404 berulang otomatis di-DROP ke firewall:
Tambahkan tugas cron otomatis di crontab root:
```bash
crontab -e
```
Tambahkan baris berikut:
```cron
# Auto-block IP yang menghasilkan >= 25 error 404 setiap 5 menit
*/5 * * * * /usr/local/bin/shsm block-scanners --threshold 25 >/dev/null 2>&1
```

---

## 7. Verifikasi dan Monitoring

Gunakan perintah-perintah berikut untuk memantau status mitigasi:
```bash
# Cek apakah ada IP yang sedang diblokir oleh connection tracking CSF
tail -f /var/log/lfd.log | grep -E "(CT|PORTFLOOD)"

# Pantau status koneksi socket web real-time
sudo -u shsm shsm collect ddos

# Cek daftar IP yang sedang diblokir di firewall
csf -d
```

