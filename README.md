# 🔎 Argus OSINT Framework
### 📡 Discover • Analyze • Report — Ethically

Argus is a professional-grade, ethical OSINT and reconnaissance framework designed for security research, blue team analysis, and authorized reconnaissance.
It emphasizes modularity, safety, auditability, and real-world threat intelligence integration.

> [!WARNING]
> **Authorized use only.** This framework is intended strictly for ethical security testing and research with proper permission.

## 🧠 Core Capabilities

### 🔍 Passive Intelligence Gathering
- **WHOIS & DNS intelligence**
- **Subdomain discovery**
- **SSL certificate & infrastructure mapping**
- **Historical endpoint discovery (Wayback)**

### ⚙️ Active Reconnaissance (Optional & Controlled)
- **Port scanning**
- **Service fingerprinting**
- **Directory enumeration**
- **Rate-limited and configurable**

### 🛡️ Threat Intelligence
- **VirusTotal reputation analysis**
- **Shodan infrastructure intelligence**
- **AlienVault OTX threat pulses**
- **Censys certificate & exposure mapping**

### 🔎 Search Intelligence
- **GitHub reconnaissance for:**
    - Exposed secrets
    - Hardcoded credentials
    - Configuration leaks
    - Sensitive references

### 📊 Reporting
- **Interactive HTML dashboard**
- **Executive-ready PDF reports**
- **Structured SQLite result storage**

### 🛑 Safety, Ethics & Compliance
- ✅ **Explicit consent confirmation before scans**
- ✅ **Full audit logging**
- ✅ **Passive-by-default execution**
- ✅ **Configurable rate limits**
- ❌ **No exploitation modules**
- ❌ **No credential brute-forcing**
- ❌ **No bypass or evasion techniques**

**This tool collects intelligence — it does not attack.**

## 🏗️ Architecture Overview

```mermaid
graph TD
    UserCLI[User CLI] --> Orchestrator
    Orchestrator[Orchestrator<br>(Workflow Engine)] --> IntelModules
    subgraph IntelModules[Intelligence Modules]
        Passive[Passive Recon]
        Active[Active Recon (optional)]
        Threat[Threat Intelligence]
        Search[Search Intelligence]
        Geo[Geo / Metadata Analysis]
    end
    IntelModules --> Reporting[Reporting Engine<br>(HTML / PDF)]
```

*Alternative Text View:*
```text
┌──────────────┐
│   User CLI   │
└──────┬───────┘
       │
┌──────▼───────────┐
│ Orchestrator     │
│ (Workflow Engine)│
└──────┬───────────┘
       │
┌──────▼──────────────────────────┐
│ Intelligence Modules            │
│ ├─ Passive Recon                │
│ ├─ Active Recon (optional)      │
│ ├─ Threat Intelligence          │
│ ├─ Search Intelligence          │
│ └─ Geo / Metadata Analysis      │
└──────┬──────────────────────────┘
       │
┌──────▼───────────┐
│ Reporting Engine │
│ (HTML / PDF)     │
└──────────────────┘
```

## 🚀 Quick Start

### 📦 Requirements
- Python 3.8+
- Git
- Internet connection (for threat APIs)

### 📥 Installation

**Windows (PowerShell)**
```powershell
git clone https://github.com/DavidKuriyan/ReconAutomation.git
cd ReconAutomation
pip install -r reporter/requirements.txt
```

**Linux / macOS**
```bash
git clone https://github.com/DavidKuriyan/ReconAutomation.git
cd ReconAutomation
pip3 install -r reporter/requirements.txt
```

### ▶️ Usage

**Interactive Mode (Recommended)**
```powershell
.\run_scan.bat
```

**CLI Mode**
```bash
python orchestrator/orchestrator.py target.com --mode full
```

**Available modes:**
- `passive`
- `active`
- `intel`
- `full`

## 🔐 API Configuration

Create a local environment file:
```bash
cp .env.example .env.local
```

> [!CAUTION]
> **Never commit `.env.local`**

### Supported APIs

| Service | Purpose | Free Tier |
| :--- | :--- | :--- |
| **VirusTotal** | Domain/IP reputation | 500 req/day |
| **Shodan** | Ports, services, CVEs | Limited |
| **AlienVault OTX** | Threat pulses | Unlimited |
| **Censys** | Infra & certificates | Limited |
| **GitHub** | Code intelligence | 5000 req/hr |
| **HIBP** | Breach intelligence | ❌ Paid |

### Where APIs Are Used

**PASSIVE / THREAT INTEL**
- ├─ VirusTotal
- ├─ Shodan
- ├─ AlienVault OTX
- └─ Censys

**SEARCH INTELLIGENCE**
- └─ GitHub

**BREACH INTELLIGENCE**
- └─ Have I Been Pwned

### ⚙️ Configuration

Edit `orchestrator/config.py` to control:
- API rate limits
- Timeouts
- Threading concurrency
- Module enable/disable
- Scan safety thresholds

## 📁 Project Structure

```text
ReconAutomation/
├── orchestrator/
│   ├── orchestrator.py
│   ├── config.py
│   └── modules/
│       ├── passive_recon.py
│       ├── active_recon.py
│       ├── threat_intel.py
│       └── search_intel.py
├── reporter/
│   ├── reporter.py
│   ├── aether.db
│   └── templates/
├── .env.example
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── ETHICAL_GUIDELINES.md
└── LICENSE
```

## 🤝 Contributing

Contributions are welcome.
1. Fork the repository
2. Create a feature branch
3. Follow coding & ethics guidelines
4. Submit a Pull Request

Please read:
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [ETHICAL_GUIDELINES.md](ETHICAL_GUIDELINES.md)

## ⚖️ License & Legal Disclaimer

**MIT License**

> [!IMPORTANT]
> This framework is provided for **educational and authorized security testing only**.
> The developers assume no liability for misuse.

**By using Argus OSINT Framework, you agree to operate within legal and ethical boundaries.**
