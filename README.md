# GhostRecon

GhostRecon adalah alat all-in-one berbasis Python untuk melakukan Information Gathering, Subdomain Enumeration, Port Scanning, Vulnerability Scanning, dan keamanan web assessment secara komprehensif.

## ✨ Fitur Utama

- ⚡ WHOIS & DNS Enumeration
- 📶 Subdomain Enumeration dengan Subfinder
- 🚧 Port Scanning cepat (common ports)
- 🛡️ HTTP Headers, Security Headers, TLS/SSL checks
- 🚀 Directory brute-force dengan FFUF
- 🤝 CMS Detection, GitHub Exposure, Git Dorking
- 🛡️ Vulnerability Detection dengan Nuclei
- 🗃 Historical Data Exposure (Wayback Machine)
- 📼 FTP Anonymous Login Check
- 🌎 Summary Output lengkap dalam file hasil

## ⚙️ Instalasi

```bash
sudo apt update && sudo apt install -y python3 python3-pip ffuf nmap whatweb nuclei subfinder
pip3 install -r requirements.txt
```

## 💻 Penggunaan

```bash
python3 scan.py
```

Kemudian masukkan nama domain target seperti `example.com`.

## 💡 Output

- Semua hasil scan ditampilkan secara real-time
- File hasil akan disimpan dalam format: `namadomain_hasil.txt`

## 🌌 Contoh Hasil Ringkasan

```
[+] Registrar: PANDI
[+] DNS Records: {A: [...], MX: [...], NS: [...]}
[+] Open Ports: [80, 443]
[+] Server Header: Apache
[+] CSP: Tidak ada
[+] SSL/TLS Info: Tersedia
[+] Subdomains Found: [...]
[+] FTP Anonymous: Tidak diizinkan
```

## ⚠️ Penolakan Tanggung Jawab

Script ini dikembangkan murni untuk **riset keamanan dan edukasi**. Penggunaan untuk tujuan ilegal merupakan tanggung jawab penuh pengguna.

## ✍️ Kredit

Orchestrator Script by [@rskabc](https://github.com/rskabc)

---
