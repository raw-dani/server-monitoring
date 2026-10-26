# Rencana Implementasi: Fitur Anti-Spam & IP Blacklist Protection (SHSM)

## 1. Latar Belakang & Tujuan
Malware web (terutama pada lingkungan WordPress/PHP) atau akun email yang terkompromikan sering kali memanfaatkan server untuk mengirimkan jutaan email spam (*spam blast* atau *outbound spam bot*). Dampak fatalnya:
1. IP publik server masuk daftar hitam (**DNSBL/RBL blacklist** seperti Spamhaus, Barracuda, SpamCop).
2. Email sah dari domain milik server akan ditolak atau masuk spam folder.
3. Reputasi IP dan domain hancur dan proses delisting memakan waktu lama.

**Tujuan modul baru ini:**
Mendeteksi anomali pengiriman spam dan status IP blacklist secara dini dengan pendekatan **zero-impact/lightweight** (hemat CPU, RAM, & Disk I/O) tanpa mengubah prinsip SHSM (**Strictly Read-Only**).

---

## 2. Prinsip Efisiensi Resource (Anti-Overhead / Ultra-Lightweight)
Untuk menjamin aplikasi **TIDAK memberatkan server**:
1. **Tidak Ada Daemon/Background Loop Terus-menerus**:
   - Beroperasi berbasis *systemd timer* (sekali jalan langsung keluar/exit, membebaskan memori kembali).
2. **DNS Asinkron & Caching untuk RBL**:
   - Query DNSBL hanya dilakukan ke IP server publik sekali per siklus (misal: setiap 6 atau 12 jam).
   - Menggunakan reverse DNS resolution langsung ke server DNSBL (query UDP super ringan < 1 KB, latency < 50ms, timeout 2 detik).
3. **Pemeriksaan Mail Queue Non-Intrusif**:
   - Menggunakan pembacaan status direktori queue Postfix (`qshape` atau menghitung file queue) atau CLI `mailq`/`postqueue -p` dengan batas *timeout* ketat (3 detik).
   - Interval pemeriksaan queue: tiap 10–15 menit (hanya memakan ~10ms CPU time).
4. **Outbound Socket Anomaly Filtering**:
   - Membaca `/proc/net/tcp` atau mengeksekusi `ss -ntp state established '( dport = :25 or dport = :465 or dport = :587 )'` secara selektif.
   - Tidak memakan CPU I/O karena data soket diambil langsung dari memori kernel Linux.

---

## 3. Komponen Arsitektur Baru

### A. Subsystem 1: `RBL / IP Blacklist Scanner` (`src/shsm/security/rbl.py`)
* **Frekuensi:** Tiap 6 jam (atau 12 jam sekali via systemd timer).
* **Mekanisme Kerja:**
  1. Mendapatkan IP publik server (dari cache SHSM atau network config).
  2. Melakukan *Reverse IP format* (contoh: `1.2.3.4` -> `4.3.2.1.<dnsbl-domain>`).
  3. Query ke RBL Provider utama:
     - `zen.spamhaus.org`
     - `b.barracudacentral.org`
     - `bl.spamcop.net`
     - `dnsbl.sorbs.net`
     - `psbl.surriel.com`
     - `uceprotect.net`
  4. Deteksi status: Jika ada respons return `127.0.0.X`, IP terindikasi terdaftar (Blacklisted).
  5. Menghitung skor penalti keamanan (**Security Score deduction**).

### B. Subsystem 2: `Mail Anomaly & Queue Collector` (`src/shsm/collectors/mail_queue.py`)
* **Frekuensi:** Tiap 10–15 menit.
* **Mekanisme Kerja:**
  1. **Queue Size Audit**:
     - Membaca jumlah email aktif/deferred di Postfix queue (`/var/spool/postfix/deferred` dan `active`).
     - Alert Thresholds:
       - *Warning*: > 100 email tertahan.
       - *Critical*: > 500 email tertahan (indikasi kuat spam outbreak).
  2. **Top Sender Identification**:
     - Jika queue membengkak, ekstrak *top sender envelope* (user Linux atau domain pengirim terbanyak) untuk mengetahui akun/vhost sumber spam.
  3. **Outbound Direct SMTP Connection Detector**:
     - Memeriksa apakah ada proses PHP/user selain `postfix`/`mail` yang membuka koneksi outbound ke port 25/465/587.

---

## 4. Rencana Perubahan File & Struktur Kode

```
src/shsm/
├── collectors/
│   ├── mail_queue.py        # [BARU] Pengumpul metrik antrean mail & koneksi SMTP liar
├── security/
│   └── rbl.py               # [BARU] DNSBL Blacklist scanner (Spamhaus, Barracuda, dll.)
├── config.py                # Penambahan konfigurasi threshold mail queue & daftar RBL
├── database/
│   └── schema.py            # Tabel baru: mail_metrics & rbl_status
systemd/
├── shsm-rbl.service         # Systemd service isolasi RBL
├── shsm-rbl.timer           # Dijalankan tiap 6 atau 12 jam
├── shsm-mail.service        # Systemd service mail queue
└── shsm-mail.timer          # Dijalankan tiap 10-15 menit
```

---

## 5. Rencana Pengujian (Testing & Validation)
1. **Unit Test**:
   - Mock DNS query untuk RBL (skenario clean IP vs blacklisted IP).
   - Mock Postfix queue output (`mailq`/file counting).
2. **Benchmark Resource / Performance**:
   - Uji konsumsi RAM: Memastikan memori footprint < 35 MB saat eksekusi.
   - Uji waktu eksekusi: Scanner selesai di bawah < 3 detik.
3. **Alerting Test**:
   - Simulasi alert saat threshold queue terlampaui atau RBL positif.

---

## 6. Rekomendasi Hardening Pasif (Opsional di Dokumen SHSM)
Menyertakan panduan di `docs/SECURITY.md` untuk konfigurasi firewall VPS:
- Blokir outbound port 25 untuk selain user `postfix` (`iptables`/`ufw` owner match).
- Ini memastikan jika ada script PHP malware yang disusupkan hacker, script tersebut gagal mengirim email ke luar.
