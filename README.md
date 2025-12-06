# WiFi Router Exploit & Brute Force Scanner

A Python-based security assessment tool for TP-Link and Tenda WiFi routers. Combines exploitation techniques with dictionary-based password attacks to identify weak credentials on local networks.

## Features

- **Network Scanning**: Nmap integration for discovering routers on specified networks
- **TP-Link Bruteforce**: Get credentials using bruteforce attack.
- **Tenda Exploitation**: Config file extraction and brute-force attack capabilities
- **Multi-device Support**: Automatic router identification and protocol selection
- **Credential Management**: Load passwords from file or command-line, auto-persist discovered credentials
- **Structured Results**: Success/failure reporting with saved configurations

## Usage

### Basic Nmap Scan
```bash
python main.py -n 10.0.0.0/24 -p admin password123
```
From Nmap XML Results

```bash
python main.py -f nmap.xml -P passwords.txt -o results.txt
```
Direct IP List

```bash
python main.py -i 10.0.0.1:8080 10.0.0.2:80 -p admin password123
```

### Options
- -n, --networks: Space-separated list of CIDR networks to scan
- -f, --input_file: Path to nmap XML results file
- -i, --ip_ports: Space-separated list of target IP:port combinations
- -p, --passwords: Space-separated list of passwords to try
- -P, --password_file: Path to file containing passwords (one per line)
- -o, --output: Output file path (default: results.txt)

Note: Either -n, -f, or -i is required; either -p or -P is required.

## Credits
This project builds upon research and exploits from:

- [tp_link_gdpr](https://github.com/0xf15h/tp_link_gdpr.git) - GDPR config download vulnerability exploitation for TP-Link devices
- [CVE-2020-35391](https://github.com/H454NSec/CVE-2020-35391) - Public disclosure and PoC for Tenda password extraction.

## Requirements
- Python 3.8+
- requests
- urllib3
- nmap (for network scanning)

Install dependencies:
```bash
pip install requests urllib3
```

### Legal Disclaimer
This tool is designed for authorized security testing and educational purposes only. Unauthorized access to network systems is illegal. Ensure you have explicit permission before scanning or testing any network or device you do not own or have authority over.