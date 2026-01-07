# Aether-Recon: Ultimate High-Fidelity OSINT Framework

A professional-grade, distributed reconnaissance framework inspired by Netcraft, TheHarvester, and Amass.
**Zero-Dependency Mode**: No Docker, Redis, or Go required. Optimized for Python.

## 🌟 Key Capabilities
*   **Deep Passive Recon**:
    *   **Identity**: Native WHOIS parsing without external tool dependencies.
    *   **DNS**: Threaded multi-record enumeration (A, NS, MX, TXT, SOA).
    *   **Subdomains**: Hybrid discovery using **subfinder** (if installed) and **crt.sh** (Passive fallback).
    *   **SSL Intel**: Certificate validity, issuers, and subject details.
    *   **Email Harvesting**: Scrapes target pages for email addresses (TheHarvester-Lite).
*   **Active Reconnaissance**:
    *   **Port Scanning**: Uses **Nmap** if available, or falls back to a custom **Python Socket Scanner** with **Banner Grabbing** (Service/Version detection).
    *   **SMTP Analysis**: Connects to Mail Servers to grab SMTP banners and config info.
    *   **Directory Busting**: Threaded fuzzing for sensitive paths (.git, .env, wp-admin).
    *   **Tech Detection**: Fingerprints server headers and HTML body (WordPress, React, Cloudflare).
    *   **Security Audit**: Checks for missing security headers (HSTS, CSP, X-Frame-Options).
*   **Mission Control Dashboard**:
    *   **Cyberpunk Mission Control**: Premium, dark-mode "Hacker" style dashboard with neon accents.
    *   **Single-Page Experience**: Instant navigation between Dashboard, Network Map, Web Recon, and Vulnerabilities.
    *   **Vulnerability Tracking**: dedicated section for security findings with severity scoring.
    *   **Visual Analytics**: Interactive cards for Port distribution, Tech stack, and Subdomain enumeration.

## 🚀 Usage Guide

### 1. Prerequisites
*   Python 3.8+

### 2. Installation
Install the optimized dependency set:
```powershell
cd d:\Reconnaissance\reporter
pip install -r requirements.txt
```

### 3. Initialize Database
Initialize the High-Performance SQLite engine (Enables WAL Mode for concurrency):
```powershell
python init_db.py
```
*Note: This fixes "Database Locked" errors.*

### 4. Start Dashboard
Launch the Reporting Engine to listen for scan events:
```powershell
python reporter.py
```

### 5. Launch Recon
Run the Orchestrator against any target. It automates the entire OSINT killchain.
```powershell
cd d:\Reconnaissance\orchestrator
python orchestrator.py example.com
```

## � Output
Real-time reports are saved to: `d:\Reconnaissance\reporter\reports\`

## 🛠 Troubleshooting
*   **Permissions**: Ensure you have permission to scan the target.
*   **Speed**: The tool uses threading (20 workers for ports, 10 for dirs).
*   **Missing Tools**: The system auto-detects `nmap` and `subfinder`. If missing, robust Python fallbacks are triggered automatically.
