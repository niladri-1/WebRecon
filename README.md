# <div align="center"> WebRecon 🕸️ </div>

<div align="center">

![WebRecon Banner](https://img.shields.io/badge/WebRecon-v2.0-blue?style=for-the-badge&logo=security&logoColor=white)

[![Python](https://img.shields.io/badge/python-3.6+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://linux.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/niladri-1/WebRecon?style=for-the-badge&logo=github)](https://github.com/niladri-1/WebRecon/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/niladri-1/WebRecon?style=for-the-badge&logo=github)](https://github.com/niladri-1/WebRecon/network)

**Advanced Web Reconnaissance Tool for Cybersecurity Professionals**

*Comprehensive web security assessment and information gathering toolkit*

</div>

---

## 🎯 About

WebRecon is a powerful, all-in-one web reconnaissance tool designed for cybersecurity professionals, penetration testers, and security researchers. It automates the process of gathering critical information about web targets, identifying potential vulnerabilities, and generating comprehensive reports.

## ✨ Features

### 🔍 **Information Gathering**
- **DNS Resolution & Analysis** - Resolve IP addresses and enumerate DNS records
- **WHOIS Lookup** - Retrieve domain registration information
- **Geolocation Detection** - Identify server location and ISP details
- **HTTP Header Analysis** - Extract server and security header information

### 🌐 **Network Reconnaissance**
- **Port Scanning** - Scan common ports with multi-threaded efficiency
- **Subdomain Enumeration** - Discover subdomains using wordlist techniques
- **Service Detection** - Identify services running on open ports

### 💻 **Web Application Analysis**
- **Technology Detection** - Identify web technologies, frameworks, and CMS
- **Directory Enumeration** - Discover hidden directories and files
- **SSL/TLS Certificate Analysis** - Examine SSL certificates and configurations

### 🛡️ **Security Assessment**
- **Vulnerability Assessment** - Identify common security misconfigurations
- **Security Header Analysis** - Check for missing security headers
- **Information Disclosure Detection** - Find exposed sensitive information

### 📊 **Reporting**
- **Comprehensive Reports** - Generate detailed Markdown reports
- **JSON Data Export** - Export raw scan data for further analysis
- **Organized Results** - Timestamped results with structured output

## 🚀 Installation

### Prerequisites
- Python 3.6 or higher
- Linux/Unix operating system
- Required system tools: `curl`, `dig`, `whois`, `openssl`

### Install Dependencies
```bash
# Update system packages
sudo apt update

# Install required system tools
sudo apt install curl dnsutils whois openssl

# Clone the repository
git clone https://github.com/niladri-1/WebRecon.git
cd WebRecon

# Make the script executable
chmod +x webrecon.py
```

## 🔧 Usage

### Basic Usage
```bash
# Run WebRecon
python3 webrecon.py

# Or run directly
./webrecon.py
```

### Interactive Menu
WebRecon provides an intuitive interactive menu with the following options:

1. **Full Reconnaissance** - Complete automated scan
2. **Basic Info Gathering** - IP, DNS, and basic headers
3. **Port Scanning** - Scan for open ports
4. **Subdomain Enumeration** - Find subdomains
5. **Technology Detection** - Identify web technologies
6. **Directory Enumeration** - Find hidden directories
7. **SSL/TLS Analysis** - SSL certificate information
8. **DNS Enumeration** - DNS records analysis
9. **Vulnerability Assessment** - Basic security checks
10. **Generate Report** - Create detailed reports

### Example Commands
```bash
# Example target input
Enter target URL: https://example.com
# or
Enter target URL: example.com
```

## 📁 Output Structure

```
results/
└── scan_20241129_143022/
    ├── README.md          # Comprehensive report
    └── scan_data.json     # Raw scan data
```

## 🔍 Scan Modules

### Port Scanning
- Scans common ports (21, 22, 23, 25, 53, 80, 443, etc.)
- Multi-threaded for faster results
- Service identification

### Subdomain Enumeration
- Uses common subdomain wordlist
- Concurrent DNS resolution
- IP address mapping

### Technology Detection
- Identifies CMS (WordPress, Joomla, Drupal)
- Web servers (Apache, Nginx, IIS)
- Frameworks (Laravel, Django, React, etc.)
- Programming languages (PHP, ASP.NET)

### Directory Enumeration
- Common directory wordlist
- HTTP status code analysis
- Hidden resource discovery

### Security Analysis
- Missing security headers detection
- Information disclosure checks
- Basic vulnerability assessment

## 🛠️ Technical Details

### System Requirements
- **OS**: Linux/Unix (Ubuntu, Debian, CentOS, etc.)
- **Python**: 3.6+
- **Memory**: 512MB RAM minimum
- **Disk**: 100MB free space

### Dependencies
- `subprocess` - System command execution
- `socket` - Network operations
- `ssl` - SSL/TLS analysis
- `json` - Data serialization
- `threading` - Concurrent operations
- `urllib.parse` - URL parsing

### Network Tools
- `curl` - HTTP requests and header analysis
- `dig` - DNS queries and record enumeration
- `whois` - Domain registration information
- `openssl` - SSL certificate analysis

## 📊 Sample Report

```markdown
# Web Reconnaissance Report

**Target URL:** https://example.com
**Target Domain:** example.com
**Scan Date:** 2024-11-29 14:30:22

## 🔍 Basic Information
**IP Address:** 93.184.216.34
**Location:** Norwell, United States
**ISP:** Edgecast

## 🔓 Open Ports
| Port | Service |
|------|---------|
| 80   | HTTP    |
| 443  | HTTPS   |

## 💻 Technologies Detected
- Apache Server
- PHP
- WordPress
```

## 🎨 Features Highlight

### 🎯 **Multi-threaded Performance**
- Concurrent port scanning
- Parallel subdomain enumeration
- Efficient resource utilization

### 🔒 **Security Focused**
- Security header analysis
- SSL/TLS certificate validation
- Vulnerability identification

### 📈 **Comprehensive Reporting**
- Markdown formatted reports
- JSON data export
- Timestamped results

### 🌈 **User-Friendly Interface**
- Colorized terminal output
- Interactive menu system
- Progress indicators

## ⚠️ Legal Disclaimer

This tool is intended for authorized penetration testing and security research purposes only. Users are responsible for complying with applicable laws and regulations. Only use this tool on systems you own or have explicit permission to test.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Guidelines
- Follow PEP 8 style guidelines
- Add comments for complex logic
- Test thoroughly before submitting
- Update documentation as needed

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **GitHub Repository**: [https://github.com/niladri-1/WebRecon](https://github.com/niladri-1/WebRecon)
- **Issues**: [https://github.com/niladri-1/WebRecon/issues](https://github.com/niladri-1/WebRecon/issues)
- **Releases**: [https://github.com/niladri-1/WebRecon/releases](https://github.com/niladri-1/WebRecon/releases)

## 📧 Contact

For questions, suggestions, or collaboration opportunities, please open an issue on GitHub.

---

<div align="center">

**⭐ If you found this tool useful, please consider giving it a star! ⭐**

[![GitHub stars](https://img.shields.io/github/stars/niladri-1/WebRecon?style=social)](https://github.com/niladri-1/WebRecon/stargazers)

</div>

---

*Made with ❤️ by [niladri-1](https://github.com/niladri-1)*