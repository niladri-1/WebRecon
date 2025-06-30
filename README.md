# 🌐 WebRecon - Advanced Web Reconnaissance Tool

**WebRecon** is a powerful reconnaissance toolkit designed for penetration testers, bug bounty hunters, and cybersecurity professionals. It automates various scanning tasks to gather intelligence and generate actionable reports on web targets.

---

<div align="center">
  <img src="./preview_img.png" alt="Project_preview" width="700">
  <p><i>WebRecon interface with colorful output and interactive menu</i></p>
</div>

## ⚙️ Installation & Run

### 🧰 Install Requirements

```bash
sudo apt update && sudo apt upgrade -y

# Install system dependencies
chmod +x setup.sh && ./setup.sh
````

### ▶ Run The Tool

```bash
sudo python3 main.py
```

---

## 📂 Project Structure

```
web-recon-tool/
├── main.py           # Main CLI interface
├── tools.py          # Reconnaissance modules
├── utils.py          # Utilities and helpers
├── requirements.txt  # Python dependencies
├── README.md         # This documentation
└── logs/             # Logs directory (auto-created)
    └── *.txt         # Timestamped scan results
```

---


## 🧪 Features

* ✅ Basic Info (IP, headers, WHOIS, GeoIP)
* ✅ Port Scanning (custom TCP + Nmap)
* ✅ Subdomain Enumeration
* ✅ Technology Fingerprinting (custom + WhatWeb)
* ✅ Directory Brute-Forcing (Gobuster/Dirb)
* ✅ SSL/TLS Certificate Review (SSLScan/OpenSSL)
* ✅ DNS Record Collection
* ✅ CMS and File Exposure Checks
* ✅ Header and Source Code Analysis
* ✅ Wordlist Generation (CeWL)
* ✅ Email Harvesting (theHarvester)
* ✅ SQL Injection Testing (sqlmap)
* ✅ Detailed Markdown + JSON Reports

---

## 📝 Output

Scan results are saved in:

```
results/scan_YYYYMMDD_HHMMSS/
├── README.md         # Markdown report
├── scan_data.json    # Structured data
```

Tool-specific logs are stored in the `logs/` folder.

---