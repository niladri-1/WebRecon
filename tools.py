#!/usr/bin/env python3
"""
Website Reconnaissance Tool - Tool Functions
Contains all reconnaissance tool implementations
"""

import requests
import re
from bs4 import BeautifulSoup
from colorama import Fore, Style
from utils import ReconUtils

class ReconTools:
    def __init__(self):
        self.utils = ReconUtils()

    def technology_detection(self, target):
        """Detect web technologies using whatweb"""
        self.utils.print_section_header("Technology Detection")

        # Clean target
        clean_target = self.utils.clean_target_url(target)

        # Try both HTTP and HTTPS
        for protocol in ['https', 'http']:
            target_url = f"{protocol}://{clean_target}"
            command = f"whatweb {target_url} --color=never --no-errors"

            result = self.utils.run_command(command, timeout=60)

            if result['success']:
                output = self.utils.format_output(
                    f"Technology Detection ({protocol.upper()})",
                    result['stdout']
                )
                print(output)
                self.utils.save_output("technology_detection", output, target)
                break
            else:
                self.utils.print_warning(f"Failed to scan {target_url}: {result['stderr']}")

        # Additional manual detection
        self._manual_tech_detection(clean_target)

    def _manual_tech_detection(self, target):
        """Manual technology detection using headers"""
        try:
            for protocol in ['https', 'http']:
                try:
                    target_url = f"{protocol}://{target}"
                    response = requests.get(target_url, timeout=10, verify=False)

                    tech_info = []
                    tech_info.append(f"Status Code: {response.status_code}")

                    # Check headers for technology indicators
                    headers = response.headers
                    if 'Server' in headers:
                        tech_info.append(f"Server: {headers['Server']}")
                    if 'X-Powered-By' in headers:
                        tech_info.append(f"X-Powered-By: {headers['X-Powered-By']}")
                    if 'X-Generator' in headers:
                        tech_info.append(f"X-Generator: {headers['X-Generator']}")

                    # Check HTML content for CMS indicators
                    soup = BeautifulSoup(response.text, 'html.parser')

                    # WordPress detection
                    if soup.find('meta', {'name': 'generator', 'content': re.compile(r'WordPress', re.I)}):
                        tech_info.append("CMS: WordPress detected")

                    # Check for common framework indicators
                    if 'wp-content' in response.text or 'wp-includes' in response.text:
                        tech_info.append("CMS: WordPress (content analysis)")

                    if tech_info:
                        output = "\n".join(tech_info)
                        formatted_output = self.utils.format_output(
                            f"Manual Technology Detection ({protocol.upper()})",
                            output
                        )
                        print(formatted_output)
                        self.utils.save_output("manual_tech_detection", formatted_output, target)
                    break

                except requests.exceptions.SSLError:
                    continue
                except requests.exceptions.RequestException:
                    continue

        except Exception as e:
            self.utils.print_error(f"Manual technology detection failed: {str(e)}")

    def port_scan(self, target):
        """Perform port scanning using nmap"""
        self.utils.print_section_header("Port Scanning")

        clean_target = self.utils.clean_target_url(target)
        common_ports = self.utils.get_common_ports()

        # Quick scan of common ports
        command = f"nmap -sS -O -sV -p {common_ports} {clean_target}"

        result = self.utils.run_command(command, timeout=300)

        if result['success']:
            output = self.utils.format_output("Port Scan Results", result['stdout'])
            print(output)
            self.utils.save_output("port_scan", output, target)
        else:
            self.utils.print_error(f"Port scan failed: {result['stderr']}")

            # Fallback to basic TCP connect scan
            fallback_command = f"nmap -sT -p {common_ports} {clean_target}"
            fallback_result = self.utils.run_command(fallback_command, timeout=180)

            if fallback_result['success']:
                output = self.utils.format_output("Port Scan Results (TCP Connect)", fallback_result['stdout'])
                print(output)
                self.utils.save_output("port_scan_fallback", output, target)
            else:
                self.utils.print_error(f"Fallback port scan also failed: {fallback_result['stderr']}")

    def directory_discovery(self, target):
        """Discover directories and files using dirb/gobuster"""
        self.utils.print_section_header("Directory Discovery")

        clean_target = self.utils.clean_target_url(target)
        wordlist = self.utils.get_wordlists_path()

        if not wordlist:
            self.utils.print_warning("No wordlist found. Trying with built-in wordlists.")
            wordlist = "/usr/share/dirb/wordlists/common.txt"

        # Try gobuster first (faster)
        for protocol in ['https', 'http']:
            target_url = f"{protocol}://{clean_target}"

            # Gobuster command
            gobuster_cmd = f"gobuster dir -u {target_url} -w {wordlist} -t 50 -q --no-error"

            result = self.utils.run_command(gobuster_cmd, timeout=300)

            if result['success'] and result['stdout'].strip():
                output = self.utils.format_output(
                    f"Directory Discovery - Gobuster ({protocol.upper()})",
                    result['stdout']
                )
                print(output)
                self.utils.save_output("directory_discovery_gobuster", output, target)
                break
            else:
                # Try dirb as fallback
                dirb_cmd = f"dirb {target_url} {wordlist} -w -S"
                dirb_result = self.utils.run_command(dirb_cmd, timeout=300)

                if dirb_result['success']:
                    output = self.utils.format_output(
                        f"Directory Discovery - Dirb ({protocol.upper()})",
                        dirb_result['stdout']
                    )
                    print(output)
                    self.utils.save_output("directory_discovery_dirb", output, target)
                    break

    def source_analysis(self, target):
        """Analyze webpage source code for secrets and credentials"""
        self.utils.print_section_header("Source Code Analysis")

        clean_target = self.utils.clean_target_url(target)

        # Patterns to search for
        patterns = {
            'API Keys': r'[aA][pP][iI][_]?[kK][eE][yY][\s]*[:=][\s]*["\']([^"\']+)["\']',
            'Passwords': r'[pP][aA][sS][sS][wW][oO][rR][dD][\s]*[:=][\s]*["\']([^"\']+)["\']',
            'Tokens': r'[tT][oO][kK][eE][nN][\s]*[:=][\s]*["\']([^"\']+)["\']',
            'AWS Keys': r'AKIA[0-9A-Z]{16}',
            'Private Keys': r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
            'Database URLs': r'[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]*',
            'Email Addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }

        findings = []

        for protocol in ['https', 'http']:
            try:
                target_url = f"{protocol}://{clean_target}"
                response = requests.get(target_url, timeout=15, verify=False)

                if response.status_code == 200:
                    content = response.text

                    # Search for patterns
                    for pattern_name, pattern in patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            findings.append(f"\n{pattern_name}:")
                            for match in matches[:5]:  # Limit to first 5 matches
                                findings.append(f"  - {match}")

                    # Look for interesting comments
                    comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
                    if comments:
                        findings.append("\nHTML Comments:")
                        for comment in comments[:3]:  # Limit to first 3 comments
                            clean_comment = comment.strip()[:100]  # First 100 chars
                            findings.append(f"  - {clean_comment}")

                    # Look for JavaScript files
                    js_files = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', content)
                    if js_files:
                        findings.append("\nJavaScript Files:")
                        for js_file in js_files[:10]:  # Limit to first 10 files
                            findings.append(f"  - {js_file}")

                    break

            except requests.exceptions.RequestException as e:
                continue

        if findings:
            output = "\n".join(findings)
            formatted_output = self.utils.format_output("Source Code Analysis", output)
            print(formatted_output)
            self.utils.save_output("source_analysis", formatted_output, target)
        else:
            self.utils.print_warning("No interesting findings in source code")

    def ssl_analysis(self, target):
        """Analyze SSL/TLS configuration"""
        self.utils.print_section_header("SSL/TLS Analysis")

        clean_target = self.utils.clean_target_url(target)

        # SSLScan
        sslscan_cmd = f"sslscan {clean_target}:443"
        result = self.utils.run_command(sslscan_cmd, timeout=120)

        if result['success']:
            output = self.utils.format_output("SSL Scan Results", result['stdout'])
            print(output)
            self.utils.save_output("ssl_analysis", output, target)
        else:
            self.utils.print_warning(f"SSLScan failed: {result['stderr']}")

            # Manual SSL check using OpenSSL
            openssl_cmd = f"echo | openssl s_client -connect {clean_target}:443 -servername {clean_target} 2>/dev/null | openssl x509 -noout -text"
            openssl_result = self.utils.run_command(openssl_cmd, timeout=30)

            if openssl_result['success']:
                output = self.utils.format_output("SSL Certificate Analysis", openssl_result['stdout'])
                print(output)
                self.utils.save_output("ssl_analysis_manual", output, target)

    def header_analysis(self, target):
        """Analyze HTTP headers for security configurations"""
        self.utils.print_section_header("HTTP Headers Analysis")

        clean_target = self.utils.clean_target_url(target)

        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy'
        ]

        findings = []

        for protocol in ['https', 'http']:
            try:
                target_url = f"{protocol}://{clean_target}"
                response = requests.get(target_url, timeout=10, verify=False)

                findings.append(f"URL: {target_url}")
                findings.append(f"Status Code: {response.status_code}")
                findings.append(f"Response Headers:\n")

                # Check all headers
                for header, value in response.headers.items():
                    findings.append(f"  {header}: {value}")

                findings.append(f"\nSecurity Headers Analysis:\n")

                # Check security headers
                for header in security_headers:
                    if header in response.headers:
                        findings.append(f"  ✓ {header}: {response.headers[header]}")
                    else:
                        findings.append(f"  ✗ {header}: Missing")

                break

            except requests.exceptions.RequestException as e:
                continue

        if findings:
            output = "\n".join(findings)
            formatted_output = self.utils.format_output("HTTP Headers Analysis", output)
            print(formatted_output)
            self.utils.save_output("header_analysis", formatted_output, target)

    def vulnerability_scan(self, target):
        """Perform vulnerability scanning using nikto"""
        self.utils.print_section_header("Vulnerability Scanning")

        clean_target = self.utils.clean_target_url(target)

        for protocol in ['https', 'http']:
            target_url = f"{protocol}://{clean_target}"

            # Nikto scan
            nikto_cmd = f"nikto -h {target_url} -C all -timeout 10"
            result = self.utils.run_command(nikto_cmd, timeout=600)

            if result['success']:
                output = self.utils.format_output(
                    f"Vulnerability Scan - Nikto ({protocol.upper()})",
                    result['stdout']
                )
                print(output)
                self.utils.save_output("vulnerability_scan", output, target)
                break
            else:
                self.utils.print_warning(f"Nikto scan failed for {target_url}: {result['stderr']}")

    def wordpress_scan(self, target):
        """Scan WordPress sites using wpscan"""
        self.utils.print_section_header("WordPress Scanning")

        clean_target = self.utils.clean_target_url(target)

        # First check if it's a WordPress site
        is_wordpress = self._check_wordpress(clean_target)

        if not is_wordpress:
            self.utils.print_warning("Target does not appear to be a WordPress site")
            return

        for protocol in ['https', 'http']:
            target_url = f"{protocol}://{clean_target}"

            # WPScan command
            wpscan_cmd = f"wpscan --url {target_url} --enumerate u,t,p --plugins-detection aggressive --disable-tls-checks"
            result = self.utils.run_command(wpscan_cmd, timeout=600)

            if result['success']:
                output = self.utils.format_output(
                    f"WordPress Scan ({protocol.upper()})",
                    result['stdout']
                )
                print(output)
                self.utils.save_output("wordpress_scan", output, target)
                break
            else:
                self.utils.print_warning(f"WPScan failed for {target_url}: {result['stderr']}")

    def _check_wordpress(self, target):
        """Check if target is running WordPress"""
        try:
            for protocol in ['https', 'http']:
                target_url = f"{protocol}://{target}"
                response = requests.get(target_url, timeout=10, verify=False)

                # Check for WordPress indicators
                wp_indicators = [
                    'wp-content', 'wp-includes', 'wp-admin',
                    'WordPress', 'wp-json', '/wp/'
                ]

                for indicator in wp_indicators:
                    if indicator in response.text:
                        return True

                # Check generator meta tag
                if 'generator' in response.text.lower() and 'wordpress' in response.text.lower():
                    return True

        except:
            pass

        return False

    def sql_injection_test(self, target):
        """Test for SQL injection vulnerabilities using sqlmap"""
        self.utils.print_section_header("SQL Injection Testing")

        clean_target = self.utils.clean_target_url(target)

        # Basic sqlmap scan
        for protocol in ['https', 'http']:
            target_url = f"{protocol}://{clean_target}"

            sqlmap_cmd = f"sqlmap -u {target_url} --batch --crawl=2 --level=1 --risk=1 --random-agent"
            result = self.utils.run_command(sqlmap_cmd, timeout=300)

            if result['success']:
                output = self.utils.format_output(
                    f"SQL Injection Test ({protocol.upper()})",
                    result['stdout']
                )
                print(output)
                self.utils.save_output("sql_injection_test", output, target)
                break
            else:
                self.utils.print_warning(f"SQLMap scan failed for {target_url}: {result['stderr']}")

    def email_harvesting(self, target):
        """Harvest emails and usernames using theHarvester"""
        self.utils.print_section_header("Email/Username Harvesting")

        clean_target = self.utils.clean_target_url(target)

        # Remove any subdomains to get base domain
        domain_parts = clean_target.split('.')
        if len(domain_parts) > 2:
            base_domain = '.'.join(domain_parts[-2:])
        else:
            base_domain = clean_target

        # theHarvester command
        harvester_cmd = f"theHarvester -d {base_domain} -l 100 -b google,bing,yahoo,duckduckgo"
        result = self.utils.run_command(harvester_cmd, timeout=180)

        if result['success']:
            output = self.utils.format_output("Email Harvesting", result['stdout'])
            print(output)
            self.utils.save_output("email_harvesting", output, target)
        else:
            self.utils.print_warning(f"Email harvesting failed: {result['stderr']}")

            # Manual email extraction from website
            self._manual_email_extraction(clean_target)

    def _manual_email_extraction(self, target):
        """Manual email extraction from website content"""
        try:
            emails = set()

            for protocol in ['https', 'http']:
                try:
                    target_url = f"{protocol}://{target}"
                    response = requests.get(target_url, timeout=10, verify=False)

                    # Extract emails using regex
                    found_emails = self.utils.extract_emails_from_text(response.text)
                    emails.update(found_emails)

                    break

                except requests.exceptions.RequestException:
                    continue

            if emails:
                output = "Emails found on website:\n" + "\n".join(sorted(emails))
                formatted_output = self.utils.format_output("Manual Email Extraction", output)
                print(formatted_output)
                self.utils.save_output("manual_email_extraction", formatted_output, target)
            else:
                self.utils.print_warning("No emails found on website")

        except Exception as e:
            self.utils.print_error(f"Manual email extraction failed: {str(e)}")

    def wordlist_generation(self, target):
        """Generate custom wordlist using cewl"""
        self.utils.print_section_header("Custom Wordlist Generation")

        clean_target = self.utils.clean_target_url(target)

        for protocol in ['https', 'http']:
            target_url = f"{protocol}://{clean_target}"

            # Generate wordlist file name
            safe_target = re.sub(r'[^\w\-_\.]', '_', clean_target)
            wordlist_file = f"logs/{safe_target}_wordlist.txt"

            # CeWL command
            cewl_cmd = f"cewl -w {wordlist_file} -d 2 -m 5 {target_url}"
            result = self.utils.run_command(cewl_cmd, timeout=180)

            if result['success']:
                # Read the generated wordlist
                try:
                    with open(wordlist_file, 'r') as f:
                        wordlist_content = f.read()

                    word_count = len(wordlist_content.split('\n'))

                    output = f"Wordlist generated successfully!\n"
                    output += f"File: {wordlist_file}\n"
                    output += f"Word count: {word_count}\n\n"
                    output += f"First 20 words:\n"
                    output += '\n'.join(wordlist_content.split('\n')[:20])

                    formatted_output = self.utils.format_output(
                        f"Wordlist Generation ({protocol.upper()})",
                        output
                    )
                    print(formatted_output)
                    self.utils.save_output("wordlist_generation", formatted_output, target)
                    break

                except Exception as e:
                    self.utils.print_error(f"Could not read generated wordlist: {str(e)}")
            else:
                self.utils.print_warning(f"CeWL failed for {target_url}: {result['stderr']}")

    def custom_scan(self, target, tool_name, command):
        """Run a custom tool/command"""
        self.utils.print_section_header(f"Custom Scan - {tool_name}")

        result = self.utils.run_command(command, timeout=300)

        if result['success']:
            output = self.utils.format_output(f"Custom Scan - {tool_name}", result['stdout'])
            print(output)
            self.utils.save_output(f"custom_scan_{tool_name.lower()}", output, target)
        else:
            self.utils.print_error(f"Custom scan failed: {result['stderr']}")
