<div align="center">
<img width="3168" height="1344" alt="tenebrinet" src="https://github.com/user-attachments/assets/1ab1ad87-781a-4b93-948b-efba922e4efd" />

# TENEBRINET

### ⫷ Intelligent Honeypot Infrastructure ⫸

_Ubi codex in tenebris susurrat_
_(Where code whispers in the shadows)_

<br>

[![Build Status](https://img.shields.io/github/actions/workflow/status/ind4skylivey/tenebrinet/ci.yml?branch=main&style=for-the-badge&color=0d1117&labelColor=7b2cbf)](https://github.com/ind4skylivey/tenebrinet/actions)
[![Security](https://img.shields.io/badge/security-HARDENED-00ff9f?style=for-the-badge&labelColor=0d1117&color=b00020)]()
[![Python](https://img.shields.io/badge/python-3.10+-7b2cbf?style=for-the-badge&logo=python&labelColor=0d1117&logoColor=white)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-1a0033?style=for-the-badge&labelColor=0d1117&color=525252)](LICENSE)

[📡 INTEL](https://github.com/ind4skylivey/tenebrinet/wiki) •
[⚡ DEPLOY](#-deployment-protocols) •
[💀 ARCHITECTURE](#-system-architecture) •
[👁️ RECON](#-operative-modules)

</div>

---

## 📟 // SYSTEM_OVERVIEW

> **INITIALIZING TENEBRINET...**
> Target Identification: Cyber Threats
> Mode: Active Interception & Analysis

**TenebriNET** is not just a honeypot; it is an **ML-powered threat intelligence infrastructure**. Engineered for security researchers and Red Teamers who need to dissect how adversaries operate in the wild. It captures, analyzes, and visualizes attack vectors in real-time, turning darkness into actionable data.

---

## 👁️ // OPERATIVE_MODULES

| Module                   | Functionality                                                                            |  Status  |
| :----------------------- | :--------------------------------------------------------------------------------------- | :------: |
| **🕸️ Digital Simulacra** | High-fidelity emulation of **SSH, HTTP, FTP** services with realistic interactions.      | `ACTIVE` |
| **🧠 Neural Heuristics** | ML Engine that automatically classifies attacks (Recon, Brute Force, Exploits, Botnets). | `ONLINE` |
| **🗺️ Panopticon View**   | Interactive dashboard with global real-time attack map.                                  | `ONLINE` |
| **📡 Threat Feed**       | Intelligence integration with **AbuseIPDB, VirusTotal, Shodan**.                         | `LINKED` |
| **📼 Forensic Replay**   | Full recording of attack sessions for post-incident forensic analysis.                   | `READY`  |
| **🐳 Dockerized**        | One-command deployment for total environment isolation.                                  | `READY`  |

---

## ⚡ // DEPLOYMENT_PROTOCOLS

### System Requirements

- Python 3.10+
- Docker & Docker Compose (Recommended)
- PostgreSQL 14+ & Redis 6+

### Initialization Sequence

```bash
# [1] Clone the repository from the shadows
git clone https://github.com/ind4skylivey/tenebrinet.git
cd tenebrinet

# [2] Engage Docker Swarm (Recommended)
docker-compose up -d

# [3] Alternative: Manual Injection
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m tenebrinet.core.honeypot --config config/honeypot.yml

First Boot
Bash

# Initialize database schema
python scripts/init_db.py

# Execute Core System
python -m tenebrinet.core.honeypot

# Access Command Center
# > http://localhost:8080
```

## 💀 // SYSTEM_ARCHITECTURE

```mermaid
graph TD
    A[☠️ ATTACK SOURCES] -->|SSH / HTTP / Bots| B(🛡️ Honeypot Services)
    B -->|Raw Data| C{📝 Logging Layer}
    C -->|PostgreSQL + Redis| D[🧠 ML Engine]
    D -->|Threat Classification| E[🚀 FastAPI + WS]
    E -->|Real-time Feed| F[💻 Vue.js Dashboard]

    style A fill:#b00020,stroke:#333,stroke-width:2px,color:#fff
    style B fill:#1a0033,stroke:#7b2cbf,stroke-width:2px,color:#fff
    style D fill:#7b2cbf,stroke:#fff,stroke-width:2px,color:#fff
    style F fill:#0d1117,stroke:#00ff9f,stroke-width:2px,color:#fff
```

```text
[!] THREAT_CLASSIFICATION_MATRIX

    NEURAL ENGINE STATUS: ACTIVE PATTERN RECOGNITION: ENABLED

ID      CLASS               DETECTED BEHAVIOR             SIGNATURES
0x01    🔍 Reconnaissance   Mapping network topology      Port scans, Service enum
0x02    🔐 Brute Force      Identity compromise attempts  Credential stuffing, Spraying
0x03    💥 Exploitation     Vulnerability leveraging      CVE payloads, Shellcode
0x04    🦠 Malware Drop     Payload delivery              Binary upload, chmod +x
0x05    🤖 Botnet           Distributed coordination      C2 Callbacks, DDoS pattern
```

## ⚙️ // CONFIGURATION_VECTORS

```yaml
# /etc/tenebrinet/config/honeypot.yml

services:
  ssh:
    enabled: true
    port: 2222
    # Deception: Pretend to be an old Ubuntu server
    banner: "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"

ml:
  model: "random_forest"
  retrain_interval: "24h"

threat_intel:
  # API Keys are injected via environment variables for security
  abuseipdb_key: "${ABUSEIPDB_API_KEY}"
```

## 🤝 // ALLIANCE

The network grows stronger with each node. Check CONTRIBUTING.md to join the protocol.

Research Citation (BibTeX):

```bibtex
@software{tenebrinet2025,
  title = {TenebriNET: Intelligent Honeypot Infrastructure},
  author = {Fleming, Livey},
  year = {2025},
  url = {https://github.com/ind4skylivey/tenebrinet}
}
```

<div align="center">

🌑 Where darkness meets defense

[ SESSION TERMINATED ]

<sub>Made with 💜 & ☕ by <a href="https://github.com/ind4skylivey">ind4skylivey</a></sub>

</div>
