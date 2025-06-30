#!/bin/bash
sudo apt update && sudo apt install -y \
  nmap whatweb dirb gobuster nikto sslscan \
  wpscan sqlmap theharvester cewl curl dig whois openssl python3-pip

pip3 install -r requirements.txt

chmod +x main.py