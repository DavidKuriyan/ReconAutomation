# Argus OSINT Framework v2.0

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Python Version](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)
![Status](https://img.shields.io/badge/status-active-success)

A **professional-grade, ethical OSINT framework** with advanced intelligence gathering capabilities. Modular, safe, and robust.

## 🌟 Key Features

### **1. Modular Architecture**
- **Passive Recon**: Non-intrusive gathering (WHOIS, DNS, SSL, Subdomains).
- **Active Recon**: Port scanning, service detection, directory enumeration.
- **Threat Intel**: Integration with VirusTotal, Shodan, and AlienVault OTX.
- **Breach Intel**: Checks against Have I Been Pwned and other databases.

### **2. Safety & Ethics**
- ✅ **Strict Consent Mechanism**: Requires explicit user confirmation.
- ✅ **Audit Logging**: Tracks all actions for accountability.
- ✅ **Defensive Coding**: Handles timeouts, rate limits, and API failures gracefully.

### **3. Reporting**
- **Interactive HTML**: Searchable, sortable, and visually rich reports.
- **Professional PDF**: Executive summaries and detailed technical findings.

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.8+
- Git

### 2. Installation

```powershell
# Navigate to repository
cd "d:\Cyber security Projects\Reconnaissance"

# Install dependencies
cd reporter
pip install -r requirements.txt
```

### 3. Usage

**Interactive Menu (Recommended)**
```powershell
.\run_scan.bat
```

**CLI (Advanced)**
```powershell
python orchestrator/orchestrator.py target.com --mode full
```

---

## 🔒 Security & Configuration

### API Keys

Copy the template and add your API keys. **Never commit this file.**

```powershell
copy .env.example .env.local
```

> **⚠️ SECURITY WARNING:** Ensure your `.env.local` file is listed in `.gitignore`. Do not share your API keys.

#### Supported APIs & Their Usage

| API | Purpose | Phase Used | Free Tier |
|-----|---------|------------|-----------|
| **VirusTotal** | Checks domain reputation against 60+ antivirus engines. Returns malicious/suspicious/clean status. | Threat Intelligence | 500 req/day |
| **Shodan** | Discovers open ports, running services, CVEs, and infrastructure details for target IPs. | Threat Intelligence | 100 queries/mo |
| **AlienVault OTX** | Checks if domain appears in community threat feeds (pulses) and provides reputation scores. | Threat Intelligence | Unlimited |
| **GitHub** | Searches public repositories for exposed credentials, configs, or code mentioning the target. | Search Intelligence | 5000 req/hr |
| **Censys** | Internet-wide scanning for exposed services, SSL certificates, and infrastructure mapping. | Threat Intelligence | 250 queries/mo |
| **HIBP** | Checks if emails from the domain appear in known data breaches. | Breach Intelligence | Requires paid key |

#### Where APIs Are Used

```
PHASE 1: PASSIVE RECONNAISSANCE
    └── Threat Intelligence Assessment
        ├── VirusTotal → Domain reputation
        ├── Shodan → IP/port/CVE lookup  
        ├── AlienVault OTX → Threat pulses
        └── Censys → Infrastructure intel

PHASE 3: SEARCH INTELLIGENCE
    └── GitHub → Code/secret exposure search
    
BREACH INTELLIGENCE
    └── HIBP → Email breach lookup
```

### Configuration

Edit `config.py` to adjust:
- Rate limits (to prevent API bans)
- Timeouts
- Threading concurrency
- Module toggles

---

## 📁 Project Structure

```
Reconnaissance/
├── orchestrator/
│   ├── orchestrator.py        # Main Coordinator & Engine
│   ├── config.py              # Configuration Management
│   └── modules/               # Intelligence Modules
│       ├── active_recon.py    # [NEW] Active Scanning Logic
│       ├── passive_recon.py   # [NEW] Passive Gathering Logic
│       ├── threat_intel.py    # VirusTotal/Shodan/OTX Integration
│       ├── geo_intelligence.py
│       └── ...
├── reporter/
│   ├── aether.db              # SQLite Database
│   ├── reporter.py            # Dashboard App
│   └── templates/             # Report Templates
├── .env.example               # Config Template
├── CONTRIBUTING.md            # [NEW] Developer Guidelines
├── CODE_OF_CONDUCT.md         # [NEW] Community Standards
└── ETHICAL_GUIDELINES.md      # Legal Framework
```

---

## 🤝 Community

We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

- **Found a bug?** Open an issue.
- **Have a feature idea?** Submit a request.
- **Want to fix code?** Open a Pull Request.

---

## 📝 License & Disclaimer

**MIT License** - See LICENSE file

**Legal Disclaimer**: This tool is for authorized security testing only. The developers are NOT liable for misuse. Users are responsible for obtaining proper authorization and complying with applicable laws.

**By using Aether-Recon, you agree to use it ethically and legally.**
