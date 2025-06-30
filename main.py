#!/usr/bin/env python3
"""
Website Reconnaissance Tool - Main Application
Author: Ethical Hacking Tool
Description: Modular reconnaissance tool for ethical penetration testing
"""

import sys
import os
from datetime import datetime
from colorama import init, Fore, Back, Style
from utils import ReconUtils
from tools import ReconTools

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class WebReconTool:
    def __init__(self):
        self.utils = ReconUtils()
        self.tools = ReconTools()
        self.target = ""

    def display_banner(self):
        """Display application banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    {Fore.RED}WEB RECONNAISSANCE TOOL{Fore.CYAN}                   ║
║                         {Fore.YELLOW}Ethical Hacking Suite{Fore.CYAN}                ║
║                                                              ║
║  {Fore.GREEN}Author: Security Researcher                                 {Fore.CYAN}║
║  {Fore.GREEN}Version: 1.0                                                {Fore.CYAN}║
║  {Fore.GREEN}Purpose: Educational & Authorized Testing Only              {Fore.CYAN}║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
        print(f"{Fore.RED}⚠️  WARNING: Only use this tool on systems you own or have explicit permission to test!{Style.RESET_ALL}")
        print(f"{Fore.RED}⚠️  Unauthorized scanning may be illegal in your jurisdiction!{Style.RESET_ALL}\n")

    def display_menu(self):
        """Display main menu options"""
        menu = f"""
{Fore.YELLOW}┌─────────────────────────────────────────────────────────────┐
│                        MAIN MENU                            │
├─────────────────────────────────────────────────────────────┤{Style.RESET_ALL}
{Fore.GREEN}│  1.  Technology Detection (whatweb)                         │
│  2.  Port Scanning (nmap)                                   │
│  3.  Directory/File Discovery (dirb/gobuster)               │
│  4.  Source Code Analysis (secrets/credentials)             │
│  5.  SSL/TLS Analysis (sslscan)                             │
│  6.  HTTP Headers Analysis                                  │
│  7.  Vulnerability Scanning (nikto)                         │
│  8.  WordPress Scanning (wpscan)                            │
│  9.  SQL Injection Testing (sqlmap)                         │
│  10. Email/Username Harvesting (theHarvester)               │
│  11. Custom Wordlist Generation (cewl)                      │{Style.RESET_ALL}
{Fore.CYAN}├─────────────────────────────────────────────────────────────┤
│  99. Run All Scans (Full Reconnaissance)                    │{Style.RESET_ALL}
{Fore.RED}│  0.  Exit                                                   │{Style.RESET_ALL}
{Fore.YELLOW}└─────────────────────────────────────────────────────────────┘{Style.RESET_ALL}
        """
        print(menu)

    def get_target(self):
        """Get target URL/IP from user"""
        while True:
            target = input(f"{Fore.YELLOW}Enter target domain/IP (e.g., example.com or 192.168.1.1): {Style.RESET_ALL}").strip()
            if target:
                # Basic validation
                if self.utils.validate_target(target):
                    self.target = target
                    print(f"{Fore.GREEN}✓ Target set to: {target}{Style.RESET_ALL}")
                    return True
                else:
                    print(f"{Fore.RED}✗ Invalid target format. Please try again.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ Target cannot be empty. Please try again.{Style.RESET_ALL}")

    def run_single_scan(self, choice):
        """Run a single scan based on user choice"""
        if not self.target:
            if not self.get_target():
                return

        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"Starting scan on target: {Fore.YELLOW}{self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        scan_functions = {
            1: ("Technology Detection", self.tools.technology_detection),
            2: ("Port Scanning", self.tools.port_scan),
            3: ("Directory Discovery", self.tools.directory_discovery),
            4: ("Source Code Analysis", self.tools.source_analysis),
            5: ("SSL/TLS Analysis", self.tools.ssl_analysis),
            6: ("HTTP Headers Analysis", self.tools.header_analysis),
            7: ("Vulnerability Scanning", self.tools.vulnerability_scan),
            8: ("WordPress Scanning", self.tools.wordpress_scan),
            9: ("SQL Injection Testing", self.tools.sql_injection_test),
            10: ("Email Harvesting", self.tools.email_harvesting),
            11: ("Wordlist Generation", self.tools.wordlist_generation)
        }

        if choice in scan_functions:
            scan_name, scan_function = scan_functions[choice]
            print(f"{Fore.BLUE}[INFO] Running {scan_name}...{Style.RESET_ALL}")
            scan_function(self.target)
        else:
            print(f"{Fore.RED}[ERROR] Invalid choice!{Style.RESET_ALL}")

    def run_all_scans(self):
        """Run all available scans"""
        if not self.target:
            if not self.get_target():
                return

        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f"FULL RECONNAISSANCE SUITE - Target: {Fore.YELLOW}{self.target}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")

        scans = [
            ("Technology Detection", self.tools.technology_detection),
            ("Port Scanning", self.tools.port_scan),
            ("Directory Discovery", self.tools.directory_discovery),
            ("Source Code Analysis", self.tools.source_analysis),
            ("SSL/TLS Analysis", self.tools.ssl_analysis),
            ("HTTP Headers Analysis", self.tools.header_analysis),
            ("Vulnerability Scanning", self.tools.vulnerability_scan),
            ("WordPress Scanning", self.tools.wordpress_scan),
            ("SQL Injection Testing", self.tools.sql_injection_test),
            ("Email Harvesting", self.tools.email_harvesting),
            ("Wordlist Generation", self.tools.wordlist_generation)
        ]

        for i, (scan_name, scan_function) in enumerate(scans, 1):
            print(f"\n{Fore.CYAN}[{i}/11] Running {scan_name}...{Style.RESET_ALL}")
            scan_function(self.target)

        print(f"\n{Fore.GREEN}✓ Full reconnaissance completed!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Check the 'logs' directory for detailed results.{Style.RESET_ALL}")

    def main(self):
        """Main application loop"""
        # Check if running as root (recommended for some tools)
        if os.geteuid() != 0:
            print(f"{Fore.YELLOW}⚠️  Some tools work better with root privileges. Consider running with sudo.{Style.RESET_ALL}")

        # Create logs directory
        self.utils.create_log_directory()

        # Check for required tools
        print(f"{Fore.BLUE}[INFO] Checking for required tools...{Style.RESET_ALL}")
        missing_tools = self.utils.check_tools()

        if missing_tools:
            print(f"{Fore.RED}[WARNING] Missing tools: {', '.join(missing_tools)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Some features may not work properly. Install missing tools for full functionality.{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✓ All tools are available!{Style.RESET_ALL}")

        while True:
            self.display_banner()
            self.display_menu()

            try:
                choice = input(f"{Fore.YELLOW}Select an option (0-11, 99): {Style.RESET_ALL}").strip()

                if choice == '0':
                    print(f"{Fore.GREEN}Thank you for using Web Reconnaissance Tool!{Style.RESET_ALL}")
                    sys.exit(0)
                elif choice == '99':
                    self.run_all_scans()
                elif choice.isdigit() and 1 <= int(choice) <= 11:
                    self.run_single_scan(int(choice))
                else:
                    print(f"{Fore.RED}✗ Invalid choice. Please select a valid option.{Style.RESET_ALL}")

                input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}")
                sys.exit(0)
            except Exception as e:
                print(f"{Fore.RED}[ERROR] An unexpected error occurred: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    app = WebReconTool()
    app.main()
