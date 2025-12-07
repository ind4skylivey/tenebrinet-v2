<div align="center">

# 🌑 TenebriNET

### Intelligent Honeypot Infrastructure

*Capture what hides in the dark*

[![Build Status](https://img.shields.io/github/actions/workflow/status/ind4skylivey/tenebrinet/ci.yml?branch=main&style=for-the-badge)](https://github.com/ind4skylivey/tenebrinet/actions)
[![Security](https://img.shields.io/badge/security-A+-00ff9f?style=for-the-badge)]()
[![Python](https://img.shields.io/badge/python-3.10+-7b2cbf?style=for-the-badge&logo=python)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-1a0033?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/ind4skylivey/tenebrinet?style=for-the-badge&color=7b2cbf)](https://github.com/ind4skylivey/tenebrinet/stargazers)

[Documentation](https://github.com/ind4skylivey/tenebrinet/wiki) • 
[Installation](#-quick-start) • 
[Architecture](#-architecture) • 
[Contribute](#-contributing)

</div>

---

## 🎯 What is TenebriNET?

**TenebriNET** is an ML-powered honeypot system that captures, analyzes, and visualizes cyber threats in real-time. Built for security researchers who want to understand how attackers operate in the wild.

### ✨ Key Features

- 🕸️ **Multi-Service Honeypots** - Emulates SSH, HTTP, FTP services with realistic interactions
- 🤖 **ML-Powered Classification** - Automatically categorizes attacks (recon, brute force, exploits, malware, botnet)
- 🗺️ **Real-Time Visualization** - Interactive dashboard with global attack map
- 📊 **Threat Intelligence** - Integration with AbuseIPDB, VirusTotal, Shodan
- 🔄 **Attack Replay** - Record and replay complete attack sessions for forensic analysis
- 📡 **WebSocket Live Feed** - Real-time attack notifications
- 🐳 **Docker Ready** - One-command deployment with Docker Compose
- 📈 **Prometheus Metrics** - Production-grade monitoring and alerting

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Docker & Docker Compose (recommended)
- PostgreSQL 14+ (or use Docker)
- Redis 6+ (or use Docker)

### Installation

```bash
# Clone the repository
git clone https://github.com/ind4skylivey/tenebrinet.git
cd tenebrinet

# Option 1: Docker (Recommended)
docker-compose up -d

# Option 2: Manual Setup
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt
python -m tenebrinet.core.honeypot --config config/honeypot.yml
```

### First Run

```bash
# Initialize database
python scripts/init_db.py

# Start TenebriNET
python -m tenebrinet.core.honeypot

# Access dashboard
open http://localhost:8080
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ATTACK SOURCES                       │
│           SSH Scanners | Web Crawlers | Bots           │
└────────────────────┬────────────────────────────────────┘
                     │
          ┌──────────▼──────────┐
          │  Honeypot Services  │
          │  SSH | HTTP | FTP   │
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │   Logging Layer     │
          │   PostgreSQL + Redis│
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │    ML Engine        │
          │  Threat Classifier  │
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │   FastAPI + WS      │
          │   Real-time API     │
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │  Vue.js Dashboard   │
          │  Attack Map + Stats │
          └─────────────────────┘
```

### 📊 Threat Classification

TenebriNET's ML engine classifies attacks into 5 categories:

| Category | Description | Indicators |
|----------|-------------|------------|
| 🔍 Reconnaissance | Port scans, service enumeration | Quick connects, banner grabbing |
| 🔐 Brute Force | Credential stuffing, password spraying | Multiple login attempts |
| 💥 Exploitation | CVE attempts, command injection | Malicious payloads, shellcode |
| 🦠 Malware Deployment | Binary uploads, script execution | File transfers, chmod +x |
| 🤖 Botnet Activity | C2 callbacks, DDoS participation | Periodic connections, distributed IPs |

### 🎨 Dashboard Preview

> *Coming soon - Real-time attack visualization*

## 🛠️ Configuration

```yaml
# config/honeypot.yml
services:
  ssh:
    enabled: true
    port: 2222
    banner: "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
  
  http:
    enabled: true
    port: 8080
    fake_cms: "WordPress 5.8"

ml:
  model: "random_forest"
  retrain_interval: "24h"
  
threat_intel:
  abuseipdb_key: "${ABUSEIPDB_API_KEY}"
  virustotal_key: "${VT_API_KEY}"
```

## 📚 Documentation

- [Installation Guide](docs/guides/installation.md)
- [Architecture Deep Dive](docs/guides/architecture.md)
- [ML Model Training](docs/guides/ml-model.md)
- [API Reference](docs/api-reference.md)
- [Deployment Guide](docs/guides/deployment.md)

## 🤝 Contributing

Contributions are welcome! Please check our [Contributing Guide](CONTRIBUTING.md).

### Development Setup

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ --cov=tenebrinet

# Code formatting
black tenebrinet/
isort tenebrinet/
```

## 🔒 Security

Found a vulnerability? Please see [SECURITY.md](SECURITY.md) for responsible disclosure.

## 📖 Citation

If you use TenebriNET in your research, please cite:

```bibtex
@software{tenebrinet2025,
  title={TenebriNET: Intelligent Honeypot Infrastructure},
  author={Fleming, Livey},
  year={2025},
  url={https://github.com/ind4skylivey/tenebrinet}
}
```

## 📜 License

[MIT License](LICENSE) - see LICENSE for details.

## 🌟 Star History

![Star History Chart](https://api.star-history.com/svg?repos=ind4skylivey/tenebrinet&type=Date)

---

<div align="center">

**🌑 Where darkness meets defense**

Made with 💜 by [ind4skylivey](https://github.com/ind4skylivey)

</div>
