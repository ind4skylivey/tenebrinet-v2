# TenebriNET: Developer's Guide

> **Author:** Livey Fleming
> **Project:** TenebriNET - Intelligent Honeypot Infrastructure
> **Last Updated:** December 2025

---

## 🎯 Introduction from the Developer

When I started building TenebriNET, I had a clear vision: **create a honeypot that doesn't just log attacks—it understands them**. Traditional honeypots are passive traps that collect data but leave the heavy lifting of analysis to you. TenebriNET is different. It's an **active intelligence platform** that uses machine learning to classify threats, predict attacker behavior, and provide actionable insights in real-time.

This isn't a toy project. It's a tool designed for **security researchers, Red Teamers, and SOC analysts** who need to understand the threat landscape at a granular level. Whether you're studying credential stuffing campaigns, analyzing web exploit patterns, or tracking APT reconnaissance, TenebriNET gives you the data and context you need.

This guide will walk you through the philosophy, architecture, and practical workflows that make TenebriNET a powerful addition to your security arsenal.

---

## 📖 What is TenebriNET?

**TenebriNET** is a **containerized, ML-powered honeypot infrastructure** that emulates vulnerable services (SSH, HTTP, FTP) to attract and analyze real-world cyber attacks. Unlike traditional honeypots that simply log events, TenebriNET:

- **Classifies threats** using machine learning (e.g., brute-force, SQL injection, port scans)
- **Assigns confidence scores** to each attack based on behavioral patterns
- **Visualizes attack data** in a real-time dashboard with geolocation mapping
- **Stores structured intelligence** in PostgreSQL for long-term analysis
- **Provides an API** for integration with SIEM, SOAR, and threat intelligence platforms

### Core Philosophy

1. **Deception as Intelligence**: Attackers reveal their TTPs (Tactics, Techniques, Procedures) when they interact with realistic decoys.
2. **Automation over Manual Analysis**: ML models handle the grunt work of classification, freeing you to focus on high-value insights.
3. **Isolation by Design**: Running in Docker ensures attackers can't pivot to your real infrastructure.

---

## 🏗️ How TenebriNET Works

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      INTERNET (Attackers)                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
         ┌─────────────────────────────┐
         │   Exposed Honeypot Ports    │
         │  SSH:2222 | HTTP:8080 | ... │
         └─────────────┬───────────────┘
                       │
                       ▼
         ┌─────────────────────────────┐
         │    TenebriNET Container     │
         │  ┌─────────────────────┐    │
         │  │  Service Emulators  │    │
         │  │  (SSH/HTTP/FTP)     │    │
         │  └──────────┬──────────┘    │
         │             │                │
         │             ▼                │
         │  ┌─────────────────────┐    │
         │  │   ML Classifier     │    │
         │  │  (Threat Detection) │    │
         │  └──────────┬──────────┘    │
         │             │                │
         │             ▼                │
         │  ┌─────────────────────┐    │
         │  │  PostgreSQL + Redis │    │
         │  │  (Data Storage)     │    │
         │  └─────────────────────┘    │
         └─────────────┬───────────────┘
                       │
                       ▼
         ┌─────────────────────────────┐
         │    Dashboard (Port 8000)    │
         │  Real-time Visualization    │
         └─────────────────────────────┘
```

### Data Flow

1. **Attack Initiation**: Attacker connects to an exposed port (e.g., SSH on 2222)
2. **Service Emulation**: TenebriNET responds with realistic banners and prompts
3. **Data Capture**: All interactions (credentials, payloads, commands) are logged
4. **ML Classification**: The threat classifier analyzes the attack pattern and assigns a type + confidence score
5. **Storage**: Attack metadata is stored in PostgreSQL; session data in Redis
6. **Visualization**: The dashboard updates in real-time with new threats on the map and feed

---

## 🔒 Security Considerations

### Why Containerization Matters

Running TenebriNET in Docker provides **critical isolation**:

- **Network Segmentation**: The container has its own network namespace. Even if an attacker exploits a vulnerability, they're trapped inside.
- **Resource Limits**: Docker enforces CPU/memory limits, preventing DoS attacks from impacting your host.
- **Ephemeral Filesystem**: Changes made by attackers are lost when the container restarts.

### Best Practices

1. **Never expose TenebriNET on your production network**
   Use a dedicated VPS or cloud instance. Treat it as a DMZ.

2. **Use non-standard ports**
   While we default to 2222 (SSH), 8080 (HTTP), etc., you can map these to standard ports (22, 80) on the host to attract more traffic.

3. **Monitor resource usage**
   Attackers may attempt to exhaust resources. Set Docker limits:

   ```yaml
   deploy:
     resources:
       limits:
         cpus: "1.0"
         memory: 512M
   ```

4. **Regularly rotate credentials**
   The PostgreSQL and Redis passwords in `docker-compose.yml` should be changed in production.

5. **Enable firewall rules**
   Only allow inbound traffic on honeypot ports. Block everything else.

---

## 🛠️ Practical Workflows

### Workflow 1: Credential Harvesting Campaign Analysis

**Objective**: Identify the most commonly used credentials in SSH brute-force attacks.

**Steps**:

1. Deploy TenebriNET on a cloud VPS with port 22 mapped to the SSH honeypot.
2. Let it run for 7 days to collect data.
3. Query the database:
   ```sql
   SELECT username, password, COUNT(*) as attempts
   FROM attacks
   WHERE service = 'ssh' AND threat_type = 'credential_attack'
   GROUP BY username, password
   ORDER BY attempts DESC
   LIMIT 50;
   ```
4. **Insight**: You'll see patterns like `admin:admin`, `root:123456`, etc. Use this to harden your real systems.

### Workflow 2: Web Exploit Detection

**Objective**: Detect and analyze SQL injection attempts.

**Steps**:

1. Enable the HTTP honeypot on port 80.
2. Monitor the "Live Feed" in the dashboard for requests containing SQL keywords (`UNION`, `SELECT`, `' OR 1=1`).
3. Export attack payloads:
   ```bash
   docker exec -it tenebrinet psql -U tenebrinet -c \
     "SELECT payload FROM attacks WHERE threat_type = 'sql_injection';" > sqli_payloads.txt
   ```
4. **Insight**: Analyze the payloads to understand attacker techniques and update your WAF rules.

### Workflow 3: APT Reconnaissance Tracking

**Objective**: Identify persistent attackers (APTs) conducting reconnaissance.

**Steps**:

1. Use the "Threat Map" to visualize attack origins.
2. Filter attacks by IP address to see repeat offenders:
   ```sql
   SELECT ip, COUNT(*) as attack_count, MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
   FROM attacks
   GROUP BY ip
   HAVING COUNT(*) > 10
   ORDER BY attack_count DESC;
   ```
3. **Insight**: IPs with sustained activity over days/weeks may indicate APT reconnaissance. Cross-reference with threat intel feeds.

### Workflow 4: Deception Profile Testing

**Objective**: Test which honeypot "persona" attracts the most sophisticated attacks.

**Steps**:

1. In the dashboard, go to **Settings → Deception Profile**.
2. Switch between profiles (e.g., "Ubuntu Server" vs. "Windows IIS").
3. Compare attack types and confidence scores over a week.
4. **Insight**: Certain profiles may attract different attacker demographics (e.g., Windows targets may see more ransomware probes).

---

## 📊 Understanding the Dashboard

### Dashboard View

- **Attack Counters**: Real-time counts of SSH, HTTP, FTP attacks.
- **Trend Chart**: 24-hour attack volume graph.
- **Threat Distribution**: Pie chart showing attack types (brute-force, SQLi, port scans, etc.).

### Live Feed

- **Terminal-style log**: Shows attacks as they happen, color-coded by service.
- **Use Case**: Great for demos or live monitoring during a CTF.

### Threat Map

- **Geolocation**: Plots attack origins on a dark-themed world map.
- **Markers**: Click on a marker to see IP, threat type, and service.
- **Limitation**: Currently uses simulated coordinates. Integrate a GeoIP service (e.g., MaxMind) for real data.

### Settings

- **Port Configuration**: Toggle honeypot services on/off.
- **Target Scope**: Define IP allowlists (e.g., ignore your own testing IPs).
- **Deception Profile**: Change the system's "personality" to attract different attackers.
- **Alerting**: Configure Discord/Slack webhooks for high-confidence threats.

---

## 🧠 Machine Learning Classifier

### How It Works

TenebriNET uses a **Random Forest classifier** trained on labeled attack data. Features include:

- **Payload length**: Short payloads may indicate scans; long ones suggest exploits.
- **Character distribution**: High entropy suggests obfuscation or encoding.
- **Keyword presence**: SQL keywords, shell commands, etc.
- **Timing patterns**: Rapid-fire requests indicate automation.

### Threat Types

| Type                | Description                           | Example                      |
| ------------------- | ------------------------------------- | ---------------------------- |
| `credential_attack` | Brute-force login attempts            | SSH with `admin:password123` |
| `sql_injection`     | SQL injection payloads                | `' OR 1=1 --`                |
| `port_scan`         | Reconnaissance via port scanning      | SYN scan on multiple ports   |
| `command_injection` | Attempts to execute shell commands    | `; cat /etc/passwd`          |
| `path_traversal`    | Directory traversal attacks           | `../../etc/passwd`           |
| `ddos_attempt`      | High-volume requests from a single IP | 1000+ requests/minute        |

### Confidence Scores

- **90-100%**: High confidence. Likely a real attack.
- **70-89%**: Medium confidence. May be automated scanning.
- **<70%**: Low confidence. Could be benign traffic or misconfiguration.

---

## 🔗 Integration with Other Tools

### SIEM Integration

Export attack data to your SIEM (e.g., Splunk, ELK):

```bash
# Export as JSON
curl http://localhost:8000/api/v1/attacks?per_page=1000 > attacks.json

# Ingest into Splunk
splunk add oneshot attacks.json -sourcetype tenebrinet
```

### Threat Intelligence Feeds

Cross-reference attacker IPs with threat intel:

```python
import requests

# Get all attacker IPs
ips = requests.get('http://localhost:8000/api/v1/attacks').json()
attacker_ips = {a['ip'] for a in ips['items']}

# Check against AbuseIPDB
for ip in attacker_ips:
    resp = requests.get(f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}',
                        headers={'Key': 'YOUR_API_KEY'})
    print(f"{ip}: {resp.json()['data']['abuseConfidenceScore']}% malicious")
```

---

## 🚀 Advanced Configuration

### Custom Honeypot Services

Want to add a new service (e.g., Telnet)? Extend `BaseHoneypotService`:

```python
from tenebrinet.core.base_service import BaseHoneypotService

class TelnetHoneypot(BaseHoneypotService):
    async def handle_connection(self, reader, writer):
        writer.write(b"Welcome to TelnetOS\r\nLogin: ")
        username = (await reader.readline()).decode().strip()
        # ... capture credentials, log attack
```

### ML Model Retraining

Improve accuracy by retraining the classifier with your own data:

```bash
# Export labeled attacks
python scripts/export_training_data.py > training.csv

# Retrain model
python scripts/train_classifier.py --input training.csv --output models/classifier_v2.pkl
```

---

## 📚 Further Reading

- **MITRE ATT&CK Framework**: Map captured TTPs to the ATT&CK matrix for threat reporting.
- **OWASP Top 10**: Use TenebriNET to study real-world examples of OWASP vulnerabilities.
- **Honeypot Research Papers**: Check out academic work on honeypot design and attacker psychology.

---

## 🤝 Contributing

TenebriNET is **proprietary**, but I welcome collaboration from trusted researchers. If you have ideas for new features, ML improvements, or integration modules, reach out via [GitHub Discussions](https://github.com/ind4skylivey/tenebrinet-v2/discussions).

---

## 📧 Contact

**Livey Fleming**
GitHub: [@ind4skylivey](https://github.com/ind4skylivey)

---

_"In the shadows of the network, TenebriNET watches, learns, and reveals."_
