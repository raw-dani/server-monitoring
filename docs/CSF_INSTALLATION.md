# Panduan Instalasi & Migrasi Firewall CSF (ConfigServer Security & Firewall)

Dokumen ini berisi panduan lengkap instalasi, migrasi dari UFW/Fail2ban, serta konfigurasi awal **CSF & LFD** pada server berbasis **Ubuntu / Debian** dengan **CyberPanel & OpenLiteSpeed**.

---

## 1. Persiapan & Backup IP Terblokir

Sebelum mematikan firewall lama, simpan seluruh daftar IP yang saat ini sedang diblokir di `iptables` agar tidak hilang:

```bash
# Ekspor seluruh IP berstatus DROP/REJECT ke file backup
iptables-save | grep -E -- "-j DROP|-j REJECT" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?\b" | grep -vE "^(127\.|206\.183\.128\.56)" | sort -u > /root/blocked_ips_backup.txt

# Cek jumlah IP yang tersimpan
echo "Total IP tersimpan:" $(wc -l < /root/blocked_ips_backup.txt)
```

---

## 2. Nonaktifkan Firewall Lama (UFW & Fail2ban)

> [!WARNING]
> CSF **tidak boleh** dijalankan bersamaan dengan UFW dan Fail2ban karena akan saling menimpa rule IPTables. CSF sudah memiliki **LFD (Login Failure Daemon)** bawaan yang menggantikan seluruh fungsi Fail2ban secara otomatis.

```bash
# 1. Nonaktifkan UFW
ufw disable
systemctl stop ufw
systemctl disable ufw

# 2. Nonaktifkan Fail2ban
systemctl stop fail2ban
systemctl disable fail2ban
```

---

## 3. Instalasi Paket & Dependensi Perl

CSF membutuhkan library Perl untuk menjalankan fungsi inspeksi dan pelaporan:

```bash
apt update && apt install -y perl libwww-perl liblwp-protocol-https-perl libgd-graph-perl sendmail iptables-persistent
```

---

## 4. Download & Install CSF

Karena domain unduhan resmi asli (`download.configserver.com`) mengalami perubahan/limitasi jaringan, gunakan mirror resmi CentminMod/GitHub yang aktif:

```bash
cd /usr/src
rm -fv csf.tgz

# Download arsip installer CSF
wget https://github.com/centminmod/configserver-scripts/raw/refs/heads/main/csf.tgz -O csf.tgz

# Ekstrak dan jalankan instalasi
tar -xzf csf.tgz
cd csf
sh install.sh
```

*(Installer CSF akan otomatis mendeteksi CyberPanel dan menginstal plugin antarmuka web di `/usr/local/CyberCP/configservercsf/`).*

### Verifikasi Modul Kernel
Pastikan kernel Linux Anda mendukung seluruh modul IPTables yang dibutuhkan CSF:
```bash
perl /usr/local/csf/bin/csftest.pl
```
*Pastikan output di baris terakhir bertuliskan:*
`RESULT: csf should function on this server`

---

## 5. Konfigurasi Wajib (Pencegahan SSH Lockout)

> [!CAUTION]
> Lakukan konfigurasi port dan whitelist **sebelum** mengaktifkan CSF agar Anda tidak terkunci dari akses server.

### A. Whitelist IP Administrator
Tambahkan IP publik komputer kerja / kantor Anda ke file allow dan ignore:
```bash
cat << 'EOF' >> /etc/csf/csf.allow
# IP Administrator
36.78.113.194
114.8.219.229
206.183.128.56
127.0.0.1
EOF

cat << 'EOF' >> /etc/csf/csf.ignore
# IP Administrator
36.78.113.194
114.8.219.229
206.183.128.56
127.0.0.1
EOF
```

### B. Konfigurasi Port & Matikan Mode Testing
Edit file konfigurasi `/etc/csf/csf.conf`:
```bash
nano /etc/csf/csf.conf
```

Sesuaikan parameter berikut:
1. **Matikan Mode Testing**:
   ```ini
   TESTING = "0"
   ```
2. **Daftarkan Port Masuk & Keluar (Pastikan Port SSH Kustom terdaftar, misal `22891`)**:
   ```ini
   TCP_IN = "20,21,22,25,53,80,110,143,443,465,587,993,995,7080,8090,22891"
   TCP_OUT = "20,21,22,25,53,80,110,113,443,587,993,995,22891"
   UDP_IN = "20,21,53,80,443"
   UDP_OUT = "20,21,53,113,123"
   ```

Simpan file (`Ctrl + O`, `Enter`, `Ctrl + X`).

---

## 6. Salin IP Blacklist Lama ke `csf.deny`

Pindahkan seluruh daftar IP penyerang yang telah dibackup pada Langkah 1:

```bash
# Salin ke csf.deny
cat /root/blocked_ips_backup.txt >> /etc/csf/csf.deny

# Rapikan dari kemungkinan duplikat
sort -u /etc/csf/csf.deny -o /etc/csf/csf.deny
```

---

## 7. Aktivasi & Jalankan Layanan CSF

```bash
# Enable service agar aktif otomatis saat boot
systemctl enable csf lfd

# Restart layanan firewall dan reload rules
systemctl restart csf lfd
csf -r
```

### Verifikasi Status Akhir
Periksa apakah seluruh rule telah aktif di IPTables:
```bash
csf -l | head -30
```

---

## 8. Panduan Pengelolaan Cepat (Cheat Sheet)

| Operasi | Perintah Terminal |
| :--- | :--- |
| **Blokir IP Baru** | `csf -d <IP> "Keterangan penyerangan"` |
| **Buka Blokir IP (Unban)** | `csf -dr <IP>` |
| **Whitelist IP** | `csf -a <IP> "Deskripsi"` |
| **Cek Status Suatu IP** | `csf -g <IP>` *(Mengecek apakah IP terblokir atau lolos)* |
| **Reload Firewall** | `csf -r` |
| **Kelola via Web GUI** | Login CyberPanel (`port 8090`) -> **Security** -> **ConfigServer CSF** |

