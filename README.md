# 🛰️ NetVuS - Network Vulnerability Scanner
## Scan smart. Stay secure.

NetVuS is a lightweight, Python-based vulnerability scanner designed to quickly assess open ports and associated risks on a target host. Built for budding security analysts and networking students, it bridges the gap between practical skill-building and real-world reconnaissance techniques.

## 🔍 Features
- Fast TCP port scanning using nmap or socket

- Risk hints for exposed services (e.g., FTP, SSH, HTTP)

- Custom target + port range input

- Command-line interface for flexible scanning

- Clean and readable scan summary report

- Educational commentary on service risks

## 🚀 Getting Started
### 1. Clone the Repo
```bash
git clone https://github.com/supunhg/NetVuS_S0004.git
cd netvus
```
### 2. Install Requirements
```bash
pip install python-nmap
# Ensure nmap is installed and accessible in PATH
```
### 3. Run the Scanner
```bash
python netvus.py --target 192.168.1.1 --ports 20-1000
```

## ⚙️ Example Output
```
[*] Scanning 192.168.1.1...
[+] Port 22 (SSH) is open – Check for default credentials.
[+] Port 80 (HTTP) is open – Potential exposure to directory listing.
[✓] Scan Complete. 3 open ports detected.
```

## 💡 Why NetVuS?
This project helped me sharpen:

- Real-time port scanning logic

- Host discovery + service fingerprinting

- Cyber risk interpretation at the analyst level

- CLI tool design & Python networking modules

It’s a mini blueprint for practical vulnerability reconnaissance — and a strong first step into my cybersecurity analyst journey.

## 📁 Disclaimer
### NetVuS is for educational and ethical use only. 
#### Always scan targets you own or have explicit permission to assess.
