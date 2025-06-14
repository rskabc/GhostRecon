import subprocess
import socket
import whois
import dns.resolver
import requests
import urllib3
from bs4 import BeautifulSoup
import shutil
import re
import traceback
import os
import ftplib

summary_data = {}

print("\n============================================================")
print("GhostRecon - Advanced Reconnaissance & Vulnerability Assessment")
print("Orchestrator script by @rskabc")
print("Penolakan tanggung jawab: Script ini dibuat untuk riset keamanan.")
print("Penggunaan untuk tujuan ilegal sepenuhnya menjadi tanggung jawab pengguna.")
print("============================================================\n")

def check_dependencies():
    print("[=] Memeriksa dependensi tools...")
    tools = ['subfinder', 'metagoofil', 'nmap', 'whatweb', 'ffuf', 'nuclei']
    missing = []
    for tool in tools:
        if shutil.which(tool) is None:
            missing.append(tool)
    if missing:
        print(f"[!] Tools berikut belum terinstal: {', '.join(missing)}")
        choice = input("Apakah ingin menginstalnya sekarang? (y/n): ").lower()
        if choice == 'y':
            try:
                subprocess.run(['sudo', 'apt', 'update'])
                for tool in missing:
                    subprocess.run(['sudo', 'apt', 'install', '-y', tool])
            except Exception as e:
                print(f"[!] Gagal menginstal tools: {e}")
                exit(1)
        else:
            lanjut = input("Lanjutkan proses tanpa tools yang hilang? (y/n): ").lower()
            if lanjut != 'y':
                print("[!] Silakan instal tools yang dibutuhkan lalu jalankan ulang skrip ini.")
                exit(1)
    print("[+] Pemeriksaan tools selesai.")

def whois_lookup(domain):
    print("[=] Melakukan WHOIS lookup...")
    try:
        result = whois.whois(domain)
        summary_data['Registrar'] = result.get('registrar', 'Tidak diketahui')
        return result
    except Exception as e:
        return f"WHOIS gagal: {e}"

def dns_enum(domain):
    print("[=] Melakukan DNS enumeration...")
    results = {}
    for rtype in ['A', 'MX', 'NS']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            results[rtype] = [r.to_text() for r in answers]
        except Exception as e:
            results[rtype] = [f"Error: {e}"]
    summary_data['DNS Records'] = results
    return results

def quick_ports(domain):
    print("[=] Melakukan port scanning cepat...")
    ports = [80, 443, 21, 22]
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            if sock.connect_ex((domain, port)) == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    summary_data['Open Ports'] = open_ports
    return open_ports

def get_headers(domain):
    print("[=] Mengambil HTTP headers...")
    try:
        headers = requests.head(f'http://{domain}', timeout=5).headers
        summary_data['Server Header'] = headers.get('Server', 'Tidak diketahui')
        return headers
    except Exception as e:
        return f"HTTP request gagal: {e}"

def security_headers_check(domain):
    print("[=] Memeriksa HTTP Security Headers...")
    try:
        url = f'https://{domain}'
        response = requests.get(url, timeout=5, verify=False)
        headers = response.headers
        csp = headers.get('Content-Security-Policy', 'Tidak ada')
        cors = headers.get('Access-Control-Allow-Origin', 'Tidak ada')
        xss = headers.get('X-XSS-Protection', 'Tidak ada')
        summary_data['CSP'] = csp
        summary_data['CORS'] = cors
        summary_data['X-XSS-Protection'] = xss
        return headers
    except Exception as e:
        return f"Security header check gagal: {e}"

def https_tls_check(domain):
    print("[=] Memeriksa HTTPS & TLS/SSL...")
    try:
        result = subprocess.check_output(['nmap', '--script', 'ssl-cert,ssl-enum-ciphers', '-p', '443', domain], timeout=60).decode('utf-8')
        summary_data['SSL/TLS Info'] = 'Tersedia' if 'SSL' in result else 'Tidak ditemukan'
        return result
    except Exception as e:
        return f"SSL/TLS check gagal: {e}"

def historical_exposure(domain):
    print("[=] Mengecek exposure di Wayback Machine & GitHub...")
    try:
        wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&collapse=urlkey"
        response = requests.get(wayback_url, timeout=10)
        urls = response.text.split('\n')[:10]
        summary_data['Wayback URLs'] = urls
        return urls
    except Exception as e:
        return f"Wayback check gagal: {e}"

def ffuf_scan(domain):
    print("[=] Melakukan directory brute-force scan (ffuf)...")
    try:
        result = subprocess.check_output(['ffuf', '-u', f'http://{domain}/FUZZ', '-w', '/usr/share/wordlists/dirb/common.txt', '-mc', '200'], timeout=90).decode('utf-8')
        summary_data['Directory Scan'] = 'Selesai'
        return result
    except Exception as e:
        return f"FFUF scan gagal: {e}"

def run_subfinder(domain):
    print("[=] Menjalankan Subfinder...")
    try:
        result = subprocess.check_output(['subfinder', '-d', domain, '-silent'], timeout=90).decode('utf-8')
        subdomains = result.strip().split('\n')
        summary_data['Subdomains Found'] = subdomains
        return "\n".join(subdomains)
    except Exception as e:
        return f"Subfinder gagal: {e}"

def run_nuclei(domain):
    print("[=] Menjalankan Nuclei...")
    try:
        process = subprocess.Popen(['nuclei', '-u', f'http://{domain}'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        logs = []
        for line in iter(process.stdout.readline, b''):
            decoded_line = line.decode('utf-8').strip()
            print(decoded_line)
            logs.append(decoded_line)
        process.wait()
        summary_data['Nuclei Scan'] = logs
        return "\n".join(logs)
    except Exception as e:
        return f"Nuclei gagal: {e}"

def ftp_anonymous_check(domain):
    print("[=] Memeriksa FTP Anonymous Login...")
    try:
        ftp = ftplib.FTP()
        try:
            ftp.connect(domain, 21, timeout=5)
        except socket.gaierror as ge:
            summary_data['FTP Anonymous'] = 'DNS lookup gagal'
            return f"[!] DNS lookup gagal: {ge}"
        ftp.login(user='anonymous', passwd='')
        ftp.quit()
        summary_data['FTP Anonymous'] = 'Diperbolehkan'
        return "[!] FTP Anonymous Login Diperbolehkan"
    except Exception as e:
        summary_data['FTP Anonymous'] = 'Tidak diizinkan'
        return f"[+] FTP Anonymous Login Ditolak / Tidak tersedia"

def run_gitdorker(domain):
    print("[=] Menjalankan GitDorker untuk mengecek exposure GitHub...")
    try:
        if not os.path.exists("GitDorker"):
            subprocess.run(['git', 'clone', 'https://github.com/obheda12/GitDorker.git'])

        dork_dir = "GitDorker/dorks"
        dork_file = f"{dork_dir}/medium_dorks.txt"
        if not os.path.exists(dork_file):
            print("[!] File dorks/medium_dorks.txt tidak ditemukan. Mengunduh...")
            os.makedirs(dork_dir, exist_ok=True)
            dork_url = "https://raw.githubusercontent.com/obheda12/GitDorker/master/dorks/medium_dorks.txt"
            r = requests.get(dork_url)
            with open(dork_file, "w") as f:
                f.write(r.text)

        os.chdir("GitDorker")
        subprocess.run(['python3', 'GitDorker.py', '-q', domain, '-d', 'dorks/medium_dorks.txt', '-t', '20', '-o', f'{domain}_gitdorker.txt'])
        os.chdir("..")
        with open(f"GitDorker/{domain}_gitdorker.txt", "r") as f:
            hasil = f.read()
        summary_data['GitDorker'] = 'Laporan ditemukan'
        return hasil
    except Exception as e:
        return f"GitDorker gagal: {e}"

def summary_report(domain):
    print("\n[=] KESIMPULAN:")
    file_name = f"{domain}_hasil.txt"
    with open(file_name, "w") as f:
        for k, v in summary_data.items():
            f.write(f"[+] {k}: {v}\n")
            print(f"[+] {k}: {v}")

if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    check_dependencies()
    target = input("Masukkan domain target: ")
    print(whois_lookup(target))
    print(dns_enum(target))
    print(quick_ports(target))
    print(get_headers(target))
    print(security_headers_check(target))
    print(https_tls_check(target))
    print(historical_exposure(target))
    print(ffuf_scan(target))
    print(run_subfinder(target))
    print(run_nuclei(target))
    print(ftp_anonymous_check(target))
    print(run_gitdorker(target))
    summary_report(target)
