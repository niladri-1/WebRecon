#!/usr/bin/env python3
"""
WebRecon - Cybersecurity Reconnaissance Tool
A comprehensive web reconnaissance tool for penetration testing and security analysis
"""

import subprocess
import socket
import ssl
import json
import os
import sys
import time
import re
from urllib.parse import urlparse, urljoin
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class WebRecon:
    def __init__(self):
        self.target_url = ""
        self.target_domain = ""
        self.target_ip = ""
        self.results = {}
        self.session_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = f"results/scan_{self.session_time}"

        # Create results directory
        os.makedirs(self.output_dir, exist_ok=True)

    def banner(self):
        """Display tool banner"""
        banner_text = f"""{Colors.CYAN}
██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Colors.END}
{Colors.BOLD}{Colors.YELLOW}            Advanced Web Reconnaissance Tool v2.0{Colors.END}
{Colors.GREEN}            Developed for Cybersecurity Professionals{Colors.END}
{Colors.MAGENTA}═══════════════════════════════════════════════════════════════════════{Colors.END}
"""
        print(banner_text)

    def display_menu(self):
        """Display main menu options"""
        menu = f"""
{Colors.BOLD}{Colors.BLUE}[RECONNAISSANCE MENU]{Colors.END}
{Colors.GREEN}1.{Colors.END} {Colors.CYAN}Full Reconnaissance{Colors.END}        - Complete scan of target
{Colors.GREEN}2.{Colors.END} {Colors.CYAN}Basic Info Gathering{Colors.END}      - IP, DNS, Basic headers
{Colors.GREEN}3.{Colors.END} {Colors.CYAN}Port Scanning{Colors.END}             - Scan open ports
{Colors.GREEN}4.{Colors.END} {Colors.CYAN}Subdomain Enumeration{Colors.END}     - Find subdomains
{Colors.GREEN}5.{Colors.END} {Colors.CYAN}Technology Detection{Colors.END}      - Detect web technologies
{Colors.GREEN}6.{Colors.END} {Colors.CYAN}Directory Enumeration{Colors.END}     - Find hidden directories
{Colors.GREEN}7.{Colors.END} {Colors.CYAN}SSL/TLS Analysis{Colors.END}          - SSL certificate info
{Colors.GREEN}8.{Colors.END} {Colors.CYAN}DNS Enumeration{Colors.END}           - DNS records analysis
{Colors.GREEN}9.{Colors.END} {Colors.CYAN}Vulnerability Assessment{Colors.END}  - Basic vulnerability checks
{Colors.GREEN}10.{Colors.END} {Colors.CYAN}Generate Report{Colors.END}          - Create detailed report
{Colors.RED}0.{Colors.END} {Colors.RED}Exit{Colors.END}

{Colors.YELLOW}Choose an option:{Colors.END} """
        return input(menu)

    def get_target_info(self):
        """Get target URL from user"""
        while True:
            target = input(f"\n{Colors.BOLD}{Colors.YELLOW}Enter target URL (e.g., https://example.com): {Colors.END}")
            if target:
                if not target.startswith(('http://', 'https://')):
                    target = 'https://' + target

                parsed = urlparse(target)
                self.target_url = target
                self.target_domain = parsed.netloc

                print(f"{Colors.GREEN}[+] Target set: {Colors.CYAN}{self.target_url}{Colors.END}")
                print(f"{Colors.GREEN}[+] Domain: {Colors.CYAN}{self.target_domain}{Colors.END}")
                break
            else:
                print(f"{Colors.RED}[!] Please enter a valid URL{Colors.END}")

    def resolve_ip(self):
        """Resolve domain to IP address"""
        try:
            ip = socket.gethostbyname(self.target_domain)
            self.target_ip = ip
            self.results['ip_address'] = ip
            print(f"{Colors.GREEN}[+] IP Address: {Colors.CYAN}{ip}{Colors.END}")
            return ip
        except socket.gaierror:
            print(f"{Colors.RED}[!] Could not resolve IP address{Colors.END}")
            return None

    def get_basic_info(self):
        """Get basic information about target"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[BASIC INFO GATHERING]{Colors.END}")

        # Resolve IP
        self.resolve_ip()

        # Get HTTP headers
        self.get_http_headers()

        # Get WHOIS info
        self.get_whois_info()

        # Get geolocation
        self.get_geolocation()

    def get_http_headers(self):
        """Get HTTP headers"""
        try:
            cmd = f"curl -I -s {self.target_url}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                headers = {}
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()

                self.results['http_headers'] = headers
                print(f"{Colors.GREEN}[+] HTTP Headers retrieved{Colors.END}")

                # Check for security headers
                security_headers = ['X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                                 'Strict-Transport-Security', 'Content-Security-Policy']

                missing_headers = []
                for header in security_headers:
                    if header not in headers:
                        missing_headers.append(header)

                if missing_headers:
                    print(f"{Colors.YELLOW}[!] Missing security headers: {Colors.RED}{', '.join(missing_headers)}{Colors.END}")

        except Exception as e:
            print(f"{Colors.RED}[!] Error getting HTTP headers: {e}{Colors.END}")

    def get_whois_info(self):
        """Get WHOIS information"""
        try:
            cmd = f"whois {self.target_domain}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)

            if result.returncode == 0:
                self.results['whois'] = result.stdout
                print(f"{Colors.GREEN}[+] WHOIS information retrieved{Colors.END}")
            else:
                print(f"{Colors.YELLOW}[!] Could not retrieve WHOIS information{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error getting WHOIS: {e}{Colors.END}")

    def get_geolocation(self):
        """Get geolocation information"""
        if self.target_ip:
            try:
                # Using a command-line tool for geolocation
                cmd = f"curl -s http://ip-api.com/json/{self.target_ip}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    geo_data = json.loads(result.stdout)
                    self.results['geolocation'] = geo_data
                    print(f"{Colors.GREEN}[+] Geolocation: {Colors.CYAN}{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error getting geolocation: {e}{Colors.END}")

    def port_scan(self):
        """Perform port scanning"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PORT SCANNING]{Colors.END}")

        if not self.target_ip:
            self.resolve_ip()

        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target_ip, port))
                sock.close()

                if result == 0:
                    service = self.get_service_name(port)
                    open_ports.append({'port': port, 'service': service})
                    print(f"{Colors.GREEN}[+] Port {port} open ({service}){Colors.END}")
                    return True
                return False
            except Exception:
                return False

        print(f"{Colors.YELLOW}[*] Scanning common ports on {self.target_ip}...{Colors.END}")

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in common_ports]
            for future in as_completed(futures):
                future.result()

        self.results['open_ports'] = open_ports
        print(f"{Colors.GREEN}[+] Found {len(open_ports)} open ports{Colors.END}")

    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')

    def enumerate_subdomains(self):
        """Enumerate subdomains"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[SUBDOMAIN ENUMERATION]{Colors.END}")

        subdomains = []
        common_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'www1', 'email', 'img', 'www3',
            'help', 'shop', 'api', 'secure', 'web', 'static', 'cdn', 'media'
        ]

        def check_subdomain(sub):
            try:
                full_domain = f"{sub}.{self.target_domain}"
                ip = socket.gethostbyname(full_domain)
                subdomains.append({'subdomain': full_domain, 'ip': ip})
                print(f"{Colors.GREEN}[+] Found: {Colors.CYAN}{full_domain}{Colors.END} -> {Colors.YELLOW}{ip}{Colors.END}")
                return True
            except socket.gaierror:
                return False

        print(f"{Colors.YELLOW}[*] Enumerating subdomains for {self.target_domain}...{Colors.END}")

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in common_subs]
            for future in as_completed(futures):
                future.result()

        self.results['subdomains'] = subdomains
        print(f"{Colors.GREEN}[+] Found {len(subdomains)} subdomains{Colors.END}")

    def detect_technologies(self):
        """Detect web technologies"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[TECHNOLOGY DETECTION]{Colors.END}")

        technologies = []

        try:
            # Get page content
            cmd = f"curl -s {self.target_url}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)

            if result.returncode == 0:
                content = result.stdout.lower()

                # Technology signatures
                tech_signatures = {
                    'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                    'Joomla': ['joomla', '/media/jui/', 'option=com_'],
                    'Drupal': ['drupal', 'sites/all/', 'sites/default/'],
                    'Apache': ['apache'],
                    'Nginx': ['nginx'],
                    'PHP': ['php', '.php'],
                    'ASP.NET': ['asp.net', '__viewstate'],
                    'jQuery': ['jquery'],
                    'Bootstrap': ['bootstrap'],
                    'Angular': ['angular', 'ng-'],
                    'React': ['react'],
                    'Vue.js': ['vue.js', 'vue.min.js'],
                    'Laravel': ['laravel'],
                    'Django': ['django'],
                    'CodeIgniter': ['codeigniter'],
                    'Shopify': ['shopify'],
                    'Magento': ['magento'],
                    'WooCommerce': ['woocommerce']
                }

                for tech, signatures in tech_signatures.items():
                    for signature in signatures:
                        if signature in content:
                            technologies.append(tech)
                            print(f"{Colors.GREEN}[+] Detected: {Colors.CYAN}{tech}{Colors.END}")
                            break

                # Check headers for more technologies
                if 'http_headers' in self.results:
                    headers = self.results['http_headers']
                    server = headers.get('Server', '').lower()

                    if 'apache' in server:
                        technologies.append('Apache Server')
                    if 'nginx' in server:
                        technologies.append('Nginx Server')
                    if 'microsoft' in server:
                        technologies.append('Microsoft IIS')

                    x_powered_by = headers.get('X-Powered-By', '').lower()
                    if 'php' in x_powered_by:
                        technologies.append('PHP')
                    if 'asp.net' in x_powered_by:
                        technologies.append('ASP.NET')

                self.results['technologies'] = list(set(technologies))

        except Exception as e:
            print(f"{Colors.RED}[!] Error detecting technologies: {e}{Colors.END}")

    def directory_enumeration(self):
        """Enumerate directories"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[DIRECTORY ENUMERATION]{Colors.END}")

        directories = []
        common_dirs = [
            'admin', 'administrator', 'wp-admin', 'wp-login.php', 'login', 'panel',
            'cpanel', 'control', 'admin.php', 'admin.html', 'admin/', 'login.php',
            'login.html', 'login/', 'wp/', 'blog/', 'test/', 'demo/', 'backup/',
            'old/', 'new/', 'temp/', 'tmp/', 'uploads/', 'images/', 'img/',
            'css/', 'js/', 'includes/', 'config/', 'api/', 'v1/', 'phpmyadmin/',
            'mysql/', 'db/', 'database/', 'sql/', 'webmail/', 'mail/', 'email/'
        ]

        def check_directory(directory):
            try:
                url = urljoin(self.target_url, directory)
                cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {url}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)

                if result.returncode == 0:
                    status_code = result.stdout.strip()
                    if status_code in ['200', '301', '302', '403']:
                        directories.append({'directory': directory, 'status': status_code, 'url': url})
                        print(f"{Colors.GREEN}[+] Found: {Colors.CYAN}{directory}{Colors.END} (Status: {Colors.YELLOW}{status_code}{Colors.END})")
                        return True
                return False
            except Exception:
                return False

        print(f"{Colors.YELLOW}[*] Enumerating directories...{Colors.END}")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_directory, directory) for directory in common_dirs]
            for future in as_completed(futures):
                future.result()

        self.results['directories'] = directories
        print(f"{Colors.GREEN}[+] Found {len(directories)} accessible directories{Colors.END}")

    def ssl_analysis(self):
        """Analyze SSL/TLS certificate"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[SSL/TLS ANALYSIS]{Colors.END}")

        if not self.target_url.startswith('https://'):
            print(f"{Colors.YELLOW}[!] Target is not HTTPS, skipping SSL analysis{Colors.END}")
            return

        try:
            # Get SSL certificate info
            cmd = f"echo | openssl s_client -connect {self.target_domain}:443 -servername {self.target_domain} 2>/dev/null | openssl x509 -noout -text"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                cert_info = result.stdout
                self.results['ssl_certificate'] = cert_info
                print(f"{Colors.GREEN}[+] SSL certificate information retrieved{Colors.END}")

                # Extract key information
                if 'Subject:' in cert_info:
                    subject_line = [line for line in cert_info.split('\n') if 'Subject:' in line][0]
                    print(f"{Colors.CYAN}[*] Certificate Subject: {subject_line.split('Subject:')[1].strip()}{Colors.END}")

                if 'Issuer:' in cert_info:
                    issuer_line = [line for line in cert_info.split('\n') if 'Issuer:' in line][0]
                    print(f"{Colors.CYAN}[*] Certificate Issuer: {issuer_line.split('Issuer:')[1].strip()}{Colors.END}")

        except Exception as e:
            print(f"{Colors.RED}[!] Error analyzing SSL certificate: {e}{Colors.END}")

    def dns_enumeration(self):
        """Enumerate DNS records"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[DNS ENUMERATION]{Colors.END}")

        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

        for record_type in record_types:
            try:
                cmd = f"dig {self.target_domain} {record_type} +short"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

                if result.returncode == 0 and result.stdout.strip():
                    records = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                    dns_records[record_type] = records
                    print(f"{Colors.GREEN}[+] {record_type} records: {Colors.CYAN}{', '.join(records)}{Colors.END}")

            except Exception as e:
                print(f"{Colors.RED}[!] Error getting {record_type} records: {e}{Colors.END}")

        self.results['dns_records'] = dns_records

    def vulnerability_assessment(self):
        """Basic vulnerability assessment"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[VULNERABILITY ASSESSMENT]{Colors.END}")

        vulnerabilities = []

        # Check for common vulnerabilities
        if 'http_headers' in self.results:
            headers = self.results['http_headers']

            # Missing security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-XSS-Protection': 'XSS protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content injection protection'
            }

            for header, description in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'type': 'Missing Security Header',
                        'header': header,
                        'description': description,
                        'severity': 'Medium'
                    })

            # Check for information disclosure
            server_header = headers.get('Server', '')
            if server_header:
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'header': 'Server',
                    'value': server_header,
                    'description': 'Server information disclosed',
                    'severity': 'Low'
                })

        # Check for directory listing
        if 'directories' in self.results:
            for directory in self.results['directories']:
                if directory['status'] == '200':
                    vulnerabilities.append({
                        'type': 'Directory Accessible',
                        'directory': directory['directory'],
                        'url': directory['url'],
                        'description': 'Directory may be accessible',
                        'severity': 'Low'
                    })

        self.results['vulnerabilities'] = vulnerabilities

        if vulnerabilities:
            print(f"{Colors.YELLOW}[!] Found {len(vulnerabilities)} potential vulnerabilities{Colors.END}")
            for vuln in vulnerabilities:
                severity_color = Colors.RED if vuln['severity'] == 'High' else Colors.YELLOW if vuln['severity'] == 'Medium' else Colors.CYAN
                print(f"  {severity_color}[{vuln['severity']}] {vuln['type']}: {vuln['description']}{Colors.END}")
        else:
            print(f"{Colors.GREEN}[+] No obvious vulnerabilities found{Colors.END}")

    def generate_report(self):
        """Generate detailed report"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[GENERATING REPORT]{Colors.END}")

        report_file = os.path.join(self.output_dir, "README.md")

        try:
            with open(report_file, 'w') as f:
                f.write(f"# Web Reconnaissance Report\n\n")
                f.write(f"**Target URL:** {self.target_url}\n")
                f.write(f"**Target Domain:** {self.target_domain}\n")
                f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Report Generated by:** WebRecon v2.0\n\n")

                f.write("---\n\n")

                # Basic Information
                f.write("## 🔍 Basic Information\n\n")
                if 'ip_address' in self.results:
                    f.write(f"**IP Address:** {self.results['ip_address']}\n\n")

                if 'geolocation' in self.results:
                    geo = self.results['geolocation']
                    f.write(f"**Location:** {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}\n")
                    f.write(f"**ISP:** {geo.get('isp', 'Unknown')}\n")
                    f.write(f"**Organization:** {geo.get('org', 'Unknown')}\n\n")

                # Open Ports
                if 'open_ports' in self.results:
                    f.write("## 🔓 Open Ports\n\n")
                    if self.results['open_ports']:
                        f.write("| Port | Service |\n")
                        f.write("|------|--------|\n")
                        for port in self.results['open_ports']:
                            f.write(f"| {port['port']} | {port['service']} |\n")
                    else:
                        f.write("No open ports found in common port range.\n")
                    f.write("\n")

                # Subdomains
                if 'subdomains' in self.results:
                    f.write("## 🌐 Subdomains\n\n")
                    if self.results['subdomains']:
                        f.write("| Subdomain | IP Address |\n")
                        f.write("|-----------|------------|\n")
                        for sub in self.results['subdomains']:
                            f.write(f"| {sub['subdomain']} | {sub['ip']} |\n")
                    else:
                        f.write("No subdomains found.\n")
                    f.write("\n")

                # Technologies
                if 'technologies' in self.results:
                    f.write("## 💻 Technologies Detected\n\n")
                    if self.results['technologies']:
                        for tech in self.results['technologies']:
                            f.write(f"- {tech}\n")
                    else:
                        f.write("No specific technologies detected.\n")
                    f.write("\n")

                # Directories
                if 'directories' in self.results:
                    f.write("## 📁 Accessible Directories\n\n")
                    if self.results['directories']:
                        f.write("| Directory | Status Code | URL |\n")
                        f.write("|-----------|-------------|-----|\n")
                        for directory in self.results['directories']:
                            f.write(f"| {directory['directory']} | {directory['status']} | {directory['url']} |\n")
                    else:
                        f.write("No accessible directories found.\n")
                    f.write("\n")

                # HTTP Headers
                if 'http_headers' in self.results:
                    f.write("## 📋 HTTP Headers\n\n")
                    f.write("```\n")
                    for header, value in self.results['http_headers'].items():
                        f.write(f"{header}: {value}\n")
                    f.write("```\n\n")

                # DNS Records
                if 'dns_records' in self.results:
                    f.write("## 🔍 DNS Records\n\n")
                    for record_type, records in self.results['dns_records'].items():
                        f.write(f"**{record_type} Records:**\n")
                        for record in records:
                            f.write(f"- {record}\n")
                        f.write("\n")

                # Vulnerabilities
                if 'vulnerabilities' in self.results:
                    f.write("## ⚠️ Potential Vulnerabilities\n\n")
                    if self.results['vulnerabilities']:
                        f.write("| Severity | Type | Description |\n")
                        f.write("|----------|------|-------------|\n")
                        for vuln in self.results['vulnerabilities']:
                            f.write(f"| {vuln['severity']} | {vuln['type']} | {vuln['description']} |\n")
                    else:
                        f.write("No obvious vulnerabilities found.\n")
                    f.write("\n")

                # WHOIS Information
                if 'whois' in self.results:
                    f.write("## 📄 WHOIS Information\n\n")
                    f.write("```\n")
                    f.write(self.results['whois'])
                    f.write("```\n\n")

                # SSL Certificate
                if 'ssl_certificate' in self.results:
                    f.write("## 🔒 SSL Certificate Information\n\n")
                    f.write("```\n")
                    f.write(self.results['ssl_certificate'])
                    f.write("```\n\n")

                f.write("---\n\n")
                f.write("*Report generated by WebRecon - Advanced Web Reconnaissance Tool*\n")

            print(f"{Colors.GREEN}[+] Report saved to: {Colors.CYAN}{report_file}{Colors.END}")

            # Also save raw JSON data
            json_file = os.path.join(self.output_dir, "scan_data.json")
            with open(json_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)

            print(f"{Colors.GREEN}[+] Raw data saved to: {Colors.CYAN}{json_file}{Colors.END}")

        except Exception as e:
            print(f"{Colors.RED}[!] Error generating report: {e}{Colors.END}")

    def full_reconnaissance(self):
        """Perform full reconnaissance"""
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}[FULL RECONNAISSANCE MODE]{Colors.END}")
        print(f"{Colors.YELLOW}[*] This will perform all reconnaissance techniques...{Colors.END}")

        start_time = time.time()

        # Execute all reconnaissance modules
        self.get_basic_info()
        self.port_scan()
        self.enumerate_subdomains()
        self.detect_technologies()
        self.directory_enumeration()
        self.ssl_analysis()
        self.dns_enumeration()
        self.vulnerability_assessment()

        end_time = time.time()
        duration = end_time - start_time

        print(f"\n{Colors.BOLD}{Colors.GREEN}[RECONNAISSANCE COMPLETE]{Colors.END}")
        print(f"{Colors.CYAN}[*] Scan duration: {duration:.2f} seconds{Colors.END}")

        # Auto-generate report
        self.generate_report()

    def check_cms_vulnerabilities(self):
        """Check for CMS-specific vulnerabilities"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[CMS VULNERABILITY CHECK]{Colors.END}")

        cms_vulns = []

        if 'technologies' in self.results:
            technologies = self.results['technologies']

            # WordPress vulnerabilities
            if any('wordpress' in tech.lower() for tech in technologies):
                wp_checks = [
                    '/wp-admin/admin-ajax.php',
                    '/wp-content/debug.log',
                    '/wp-config.php.bak',
                    '/wp-content/uploads/',
                    '/.wp-config.php.swp',
                    '/wp-admin/setup-config.php'
                ]

                for check in wp_checks:
                    try:
                        url = urljoin(self.target_url, check)
                        cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {url}"
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)

                        if result.returncode == 0:
                            status_code = result.stdout.strip()
                            if status_code == '200':
                                cms_vulns.append({
                                    'cms': 'WordPress',
                                    'vulnerability': f'Accessible file: {check}',
                                    'url': url,
                                    'severity': 'Medium'
                                })
                                print(f"{Colors.YELLOW}[!] WordPress: Accessible file found - {check}{Colors.END}")
                    except Exception:
                        continue

            # Joomla vulnerabilities
            if any('joomla' in tech.lower() for tech in technologies):
                joomla_checks = [
                    '/administrator/',
                    '/configuration.php',
                    '/configuration.php-dist',
                    '/htaccess.txt',
                    '/web.config.txt'
                ]

                for check in joomla_checks:
                    try:
                        url = urljoin(self.target_url, check)
                        cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {url}"
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)

                        if result.returncode == 0:
                            status_code = result.stdout.strip()
                            if status_code == '200':
                                cms_vulns.append({
                                    'cms': 'Joomla',
                                    'vulnerability': f'Accessible file: {check}',
                                    'url': url,
                                    'severity': 'Medium'
                                })
                                print(f"{Colors.YELLOW}[!] Joomla: Accessible file found - {check}{Colors.END}")
                    except Exception:
                        continue

        if cms_vulns:
            self.results['cms_vulnerabilities'] = cms_vulns
            print(f"{Colors.RED}[!] Found {len(cms_vulns)} CMS-related issues{Colors.END}")
        else:
            print(f"{Colors.GREEN}[+] No obvious CMS vulnerabilities found{Colors.END}")

    def check_common_files(self):
        """Check for common sensitive files"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[SENSITIVE FILES CHECK]{Colors.END}")

        sensitive_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', '.env', '.git/config',
            'web.config', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'phpinfo.php', 'info.php', 'test.php', 'config.php',
            'database.sql', 'dump.sql', 'backup.sql', 'db.sql',
            'readme.txt', 'README.md', 'changelog.txt', 'version.txt',
            'config.json', 'package.json', 'composer.json', 'bower.json',
            '.DS_Store', 'Thumbs.db', '.svn/entries', '.git/HEAD'
        ]

        found_files = []

        def check_file(filename):
            try:
                url = urljoin(self.target_url, filename)
                cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {url}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)

                if result.returncode == 0:
                    status_code = result.stdout.strip()
                    if status_code in ['200', '403']:
                        found_files.append({'file': filename, 'status': status_code, 'url': url})
                        color = Colors.RED if status_code == '200' else Colors.YELLOW
                        print(f"{color}[!] Found: {filename} (Status: {status_code}){Colors.END}")
                        return True
                return False
            except Exception:
                return False

        print(f"{Colors.YELLOW}[*] Checking for sensitive files...{Colors.END}")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_file, filename) for filename in sensitive_files]
            for future in as_completed(futures):
                future.result()

        if found_files:
            self.results['sensitive_files'] = found_files
            print(f"{Colors.RED}[!] Found {len(found_files)} potentially sensitive files{Colors.END}")
        else:
            print(f"{Colors.GREEN}[+] No sensitive files found{Colors.END}")

    def run(self):
        """Main execution function"""
        self.banner()

        # Get target information
        self.get_target_info()

        while True:
            try:
                choice = self.display_menu()

                if choice == '1':
                    self.full_reconnaissance()
                elif choice == '2':
                    self.get_basic_info()
                elif choice == '3':
                    self.port_scan()
                elif choice == '4':
                    self.enumerate_subdomains()
                elif choice == '5':
                    self.detect_technologies()
                elif choice == '6':
                    self.directory_enumeration()
                elif choice == '7':
                    self.ssl_analysis()
                elif choice == '8':
                    self.dns_enumeration()
                elif choice == '9':
                    self.vulnerability_assessment()
                elif choice == '10':
                    if self.results:
                        self.generate_report()
                    else:
                        print(f"{Colors.RED}[!] No scan data available. Please run a scan first.{Colors.END}")
                elif choice == '0':
                    print(f"\n{Colors.BOLD}{Colors.GREEN}Thank you for using WebRecon!{Colors.END}")
                    print(f"{Colors.CYAN}Results saved in: {self.output_dir}{Colors.END}")
                    break
                else:
                    print(f"{Colors.RED}[!] Invalid option. Please try again.{Colors.END}")

                # Pause before returning to menu
                if choice != '0':
                    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")

            except KeyboardInterrupt:
                print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
                if self.results:
                    save_choice = input(f"{Colors.YELLOW}Save current results? (y/N): {Colors.END}")
                    if save_choice.lower() == 'y':
                        self.generate_report()
                break
            except Exception as e:
                print(f"{Colors.RED}[!] An error occurred: {e}{Colors.END}")
                continue

def check_dependencies():
    """Check if required tools are installed"""
    required_tools = ['curl', 'dig', 'whois', 'openssl']
    missing_tools = []

    for tool in required_tools:
        try:
            subprocess.run(['which', tool], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            missing_tools.append(tool)

    if missing_tools:
        print(f"{Colors.RED}[!] Missing required tools: {', '.join(missing_tools)}{Colors.END}")
        print(f"{Colors.YELLOW}[*] Please install missing tools using:{Colors.END}")
        print(f"{Colors.CYAN}sudo apt update && sudo apt install {' '.join(missing_tools)}{Colors.END}")
        return False

    return True

def main():
    """Main function"""
    try:
        # Check if running on supported system
        if os.name != 'posix':
            print(f"{Colors.RED}[!] This tool is designed for Linux/Unix systems{Colors.END}")
            sys.exit(1)

        # Check dependencies
        if not check_dependencies():
            sys.exit(1)

        # Create and run WebRecon instance
        webrecon = WebRecon()
        webrecon.run()

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Exiting...{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Fatal error: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
