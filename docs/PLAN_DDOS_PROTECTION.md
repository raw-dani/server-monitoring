# Rencana Implementasi: Fitur Anti-DDoS Protection & Early IP Blocking (SHSM)

## 1. Latar Belakang & Masalah
Serangan DDoS (Distributed Denial of Service) dan bot flood (Layer 4 SYN/TCP flood & Layer 7 HTTP flood) menjadi ancaman utama yang dapat membuat server *down* atau kehabisan CPU/RAM.

**Kelemahan Penanganan Biasa:**
- Jika serangan HTTP flood sampai diproses oleh backend (PHP / OpenLiteSpeed worker / WordPress database), server akan mengalami *resource exhaustion* (CPU 100%, RAM OOM, MySQL max connections reached).
- Membedakan antara lonjakan pengunjung asli (*spike viral*) dan serangan bot DDoS memerlukan mekanisme tantangan (*challenge verification*) tanpa memblokir pengguna sah.

**Tujuan Modul:**
1. **Early IP Blocking**: Memblokir IP penyerang di layer paling depan (Kernel Linux via `iptables`/`nftables`/`CSF`) sehingga paket ditolak sebelum diproses oleh web server.
2. **Bot vs Human Differentiation**: Memanfaatkan verifikasi *Proof-of-Work* / *JavaScript Challenge* / *reCAPTCHA* bawaan OpenLiteSpeed (OLS) serta analisis heuristik perilaku request.
3. **Zero Overhead**: SHSM memantau anomali koneksi konkuren dan status throttling tanpa menjadi proxy yang membebani traffic.

---

## 2. Arsitektur Pertahanan Berlapis (Multi-Tier Defense)

```
[ Incoming Traffic (Internet) ]
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│ Tier 1: Kernel & Firewall Layer (iptables / CSF)        │
│ - SYN-Flood protection (syncookies)                     │
│ - Port 80/443 Max Concurrent Conns per IP (ctstate)     │
│ - Packet DROP langsung di kernel (0% CPU OLS/PHP)       │
└──────────────────────────┬──────────────────────────────┘
                           │ (Traffic lolos)
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Tier 2: Web Server Engine (OpenLiteSpeed Native)        │
│ - Per-Client Request Throttling (Grace / Banning)       │
│ - Dynamic JS Challenge / reCAPTCHA for High Request IPs │
│   * Human (Browser)  -> Menjalankan JS/Captcha -> Lolos │
│   * Bot (curl/script)-> Gagal JS -> Auto-Drop 403       │
└──────────────────────────┬──────────────────────────────┘
                           │ (Traffic terverifikasi)
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Tier 3: SHSM Flood Detector & Fail2Ban Orchestration    │
│ - Audit koneksi konkuren aktif per IP                   │
│ - Audit pola burst 4xx/5xx / xmlrpc / wp-login          │
│ - Auto-Ban IP nakal ke iptables secara instan           │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Komponen yang Akan Dibuat / Dimodifikasi

### A. Subsystem 1: `DDoS & Socket Flood Collector` (`src/shsm/collectors/ddos.py`)
* **Frekuensi:** Tiap 1–5 menit (atau saat high load trigger).
* **Mekanisme Kerja:**
  1. **Audit Koneksi Konkuren per IP (Layer 4)**:
     - Mengambil ringkasan socket TCP port 80/443 dari kernel menggunakan `psutil.net_connections` atau `ss -Hnt state established '( sport = :80 or sport = :443 )'`.
     - Mengelompokkan IP sumber dan menghitung jumlah socket aktif.
     - Ambang Batas:
       - *Warning*: 1 IP > 50 koneksi konkuren.
       - *Critical*: 1 IP > 150 koneksi konkuren (indikasi kuat TCP flood / slowloris).
  2. **Audit SYN_RECV States**:
     - Memantau jumlah koneksi dalam status `SYN_RECV`. Jika > 300, sistem sedang mengalami *TCP SYN Flood*.
  3. **Auto-Mitigasi via Fail2Ban / CSF (Opsional / Non-Destructive Alerting)**:
     - Mengirimkan event ke Fail2Ban jail `shsm-ddos` untuk langsung memblokir IP di iptables selama masa ban (misal 1–24 jam).

### B. Subsystem 2: `OpenLiteSpeed Anti-DDoS & Bot Verifier Audit` (`src/shsm/security/ols_anti_ddos.py`)
* **Mekanisme Kerja:**
  1. Memeriksa file konfigurasi OpenLiteSpeed (`/usr/local/lsws/conf/httpd_config.conf`):
     - Parameter `perClientConnLimit`: memastikan ada pembatasan koneksi per IP.
     - Parameter `gracePeriod` & `banPeriod`: memastikan IP spammer di-ban sementara oleh OLS.
     - Parameter `antiDDoS` / `reCaptcha`: memastikan fitur challenge bot aktif saat load melonjak.
  2. Memberikan evaluasi skor keamanan jika OLS masih terekspos tanpa perlindungan bot challenge.

### C. Tier 1 OS Hardening Script (`scripts/harden-ddos.sh`)
* Menyediakan script iptables & sysctl kernel untuk mengaktifkan:
  - `net.ipv4.tcp_syncookies = 1`
  - `net.ipv4.tcp_max_syn_backlog = 4096`
  - `iptables` rule untuk membatasi koneksi baru port 80/443:
    ```bash
    iptables -A INPUT -p tcp --dport 80,443 -m connlimit --connlimit-above 80 -j REJECT
    ```

---

## 4. Rencana File & Struktur Kode

```
src/shsm/
├── collectors/
│   └── ddos.py               # [BARU] Pengumpul metrik flood koneksi & socket per IP
├── security/
│   └── ols_anti_ddos.py      # [BARU] Verifikator konfigurasi Anti-DDoS OLS & bot challenge
├── config.py                 # Penambahan konfigurasi ambang batas koneksi DDoS
├── core/
│   └── components.py         # Penambahan komponen ddos.conns & ddos.syn
docs/
├── PLAN_DDOS_PROTECTION.md   # [FILE INI] Dokumen arsitektur & perencanaan
scripts/
└── ddos_iptables_rules.sh    # Template rules iptables/sysctl untuk kernel level drop
```

---

## 5. Cara Membedakan Pengunjung Asli vs Bot DDoS (Detail Teknis)

| Karakteristik | Pengunjung Asli (Human) | Bot DDoS (Layer 7 Flood) |
|---|---|---|
| **Eksekusi JavaScript** | Ya (Browser Chrome/Safari/Firefox mampu merender JS) | Tidak (Script Python, curl, Go botnet biasanya tidak mengeksekusi JS engine) |
| **Pola Request** | Mengunduh HTML + CSS + JS + Gambar secara teratur | Hanya menembak endpoint dinamis (`/`, `/wp-login.php`, `POST /xmlrpc.php`) berulang-ulang |
| **Koneksi TCP Simultan** | Wajar (6–15 koneksi HTTP/2 multiplexing) | Ratusan koneksi TCP menggantung (Slowloris/Flood) |
| **Cookie Persistence** | Menyimpan cookie sesi dan token verifikasi OLS | Mengabaikan cookie / mengirim request stateless |

---

## 6. Efisiensi Resource & Jaminan "Tidak Memberatkan Server"
1. **Analisis Soket Cepat di Kernel**:
   - Pembacaan tabel koneksi dilakukan via *kernel statistics* dalam memori (waktu proses < 25 milidetik).
2. **Tidak Melakukan Reverse DNS Lookup yang Lambat**:
   - IP sumber hanya diproses dalam bentuk angka mentah (*numeric IPv4/IPv6*), tanpa query PTR lookup.
3. **Penyaringan Selektif**:
   - Hanya IP dengan koneksi di atas ambang batas yang dicatat dan dilaporkan (menghemat alokasi memori SQLite).
