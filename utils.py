#!/usr/bin/env python3
"""
Website Reconnaissance Tool - Utility Functions
Contains helper functions, validation, logging, and system checks
"""

import os
import re
import subprocess
import socket
from datetime import datetime
from urllib.parse import urlparse
from colorama import Fore, Style

class ReconUtils:
    def __init__(self):
        self.log_dir = "logs"
        self.required_tools = [
            'nmap', 'whatweb', 'dirb', 'gobuster', 'nikto',
            'sslscan', 'wpscan', 'sqlmap', 'theharvester', 'cewl'
        ]

    def create_log_directory(self):
        """Create logs directory if it doesn't exist"""
        try:
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)
                print(f"{Fore.GREEN}✓ Created logs directory{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Could not create logs directory: {str(e)}{Style.RESET_ALL}")

    def validate_target(self, target):
        """Validate target URL or IP address"""
        # Remove protocol if present
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target = parsed.netloc or parsed.path

        # Check if it's a valid IP address
        try:
            socket.inet_aton(target.split(':')[0])  # Remove port if present
            return True
        except socket.error:
            pass

        # Check if it's a valid domain name
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )

        if domain_pattern.match(target.split(':')[0]):  # Remove port if present
            return True

        return False

    def check_tools(self):
        """Check if required tools are installed"""
        missing_tools = []

        for tool in self.required_tools:
            if not self.is_tool_installed(tool):
                missing_tools.append(tool)

        return missing_tools

    def is_tool_installed(self, tool_name):
        """Check if a specific tool is installed and accessible"""
        try:
            # Use 'which' command to check if tool exists
            result = subprocess.run(['which', tool_name],
                                  capture_output=True,
                                  text=True,
                                  timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def run_command(self, command, timeout=300):
        """Execute a shell command with timeout and error handling"""
        try:
            print(f"{Fore.CYAN}[COMMAND] {command}{Style.RESET_ALL}")

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'stdout': '',
                'stderr': f'Command timed out after {timeout} seconds',
                'returncode': -1
            }
        except Exception as e:
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'returncode': -1
            }

    def save_output(self, filename, content, target):
        """Save command output to log file with timestamp"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target = re.sub(r'[^\w\-_\.]', '_', target)
            log_file = os.path.join(self.log_dir, f"{safe_target}_{filename}_{timestamp}.txt")

            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(f"Target: {target}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'='*60}\n\n")
                f.write(content)

            print(f"{Fore.GREEN}✓ Output saved to: {log_file}{Style.RESET_ALL}")
            return log_file

        except Exception as e:
            print(f"{Fore.RED}[ERROR] Could not save output: {str(e)}{Style.RESET_ALL}")
            return None

    def format_output(self, title, content, success=True):
        """Format output with colors and headers"""
        color = Fore.GREEN if success else Fore.RED
        status = "SUCCESS" if success else "FAILED"

        formatted = f"""
{color}{'='*60}
{title.upper()} - {status}
{'='*60}{Style.RESET_ALL}

{content}

{color}{'='*60}
END OF {title.upper()}
{'='*60}{Style.RESET_ALL}
        """
        return formatted

    def extract_urls_from_text(self, text):
        """Extract URLs from text content"""
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        return url_pattern.findall(text)

    def extract_emails_from_text(self, text):
        """Extract email addresses from text content"""
        email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        return email_pattern.findall(text)

    def clean_target_url(self, target):
        """Clean and normalize target URL"""
        # Remove protocol if present
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target = parsed.netloc or parsed.path

        # Remove trailing slash
        target = target.rstrip('/')

        return target

    def get_target_with_protocol(self, target, use_https=True):
        """Get target with protocol prefix"""
        if not target.startswith(('http://', 'https://')):
            protocol = 'https://' if use_https else 'http://'
            return f"{protocol}{target}"
        return target

    def print_section_header(self, title):
        """Print a formatted section header"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{title.upper()}")
        print(f"{'='*60}{Style.RESET_ALL}")

    def print_success(self, message):
        """Print success message"""
        print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")

    def print_warning(self, message):
        """Print warning message"""
        print(f"{Fore.YELLOW}⚠️  {message}{Style.RESET_ALL}")

    def print_error(self, message):
        """Print error message"""
        print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")

    def print_info(self, message):
        """Print info message"""
        print(f"{Fore.BLUE}[INFO] {message}{Style.RESET_ALL}")

    def get_common_ports(self):
        """Return list of common ports for scanning"""
        return "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080,8443"

    def get_wordlists_path(self):
        """Return common wordlist paths in Kali Linux"""
        common_paths = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
        ]

        # Return first available wordlist
        for path in common_paths:
            if os.path.exists(path):
                return path

        # If no wordlist found, return None
        return None
