## PROJECT IDENTITY

**Name:** TenebriNET  
**Tagline:** "Capture what hides in the dark"  
**Type:** ML-powered honeypot infrastructure  
**Repo:** https://github.com/ind4skylivey/tenebrinet-v2  
**Developer:** ind4skylivey (Livey Fleming)

## MISSION

Build an intelligent honeypot system that:
1. **Deceives** - Emulates vulnerable services (SSH, HTTP, FTP) to attract real attackers
2. **Captures** - Logs every interaction (credentials, commands, payloads, binaries)
3. **Analyzes** - Uses ML to classify threat types in real-time
4. **Visualizes** - Interactive dashboard with global attack map and live feed
5. **Shares** - Integrates with threat intelligence platforms (AbuseIPDB, VirusTotal)

## TECH STACK

### Backend
- **Python 3.11+** (type-hinted, async-first architecture)
- **asyncio** - Concurrent honeypot services
- **FastAPI** - REST API + WebSocket real-time feed
- **SQLAlchemy** - Async ORM for PostgreSQL
- **Redis** - Caching + rate limiting

### ML Pipeline
- **scikit-learn** - Threat classification models
- **pandas/numpy** - Data preprocessing
- **joblib** - Model persistence
- **Categories:** Reconnaissance, Brute Force, Exploitation, Malware Deployment, Botnet Activity

### Frontend
- **Vue.js 3** - Composition API
- **Chart.js** - Attack statistics
- **Leaflet** - Geolocation attack map
- **TailwindCSS** - Dark theme UI

### DevOps
- **Docker** - Containerization
- **Docker Compose** - Multi-service orchestration
- **GitHub Actions** - CI/CD pipeline
- **pytest** - Testing framework (80%+ coverage required)

## ARCHITECTURE

┌─────────────────┐ │ Attack Sources │ (Scanners, Bots, Hackers) └────────┬────────┘ │ ┌────▼─────┐ │ Services │ (SSH:2222, HTTP:8080, FTP:2121) └────┬─────┘ │ ┌────▼─────┐ │ Logging │ (PostgreSQL + Redis) └────┬─────┘ │ ┌────▼─────┐ │ ML Engine│ (Random Forest Classifier) └────┬─────┘ │ ┌────▼─────┐ │ FastAPI │ (REST + WebSocket) └────┬─────┘ │ ┌────▼─────┐ │Dashboard │ (Vue.js Attack Map) └──────────┘

## PROJECT STRUCTURE

tenebrinet/ ├── tenebrinet/ │ ├── init.py │ ├── core/ # Core infrastructure │ │ ├── honeypot.py # Main orchestrator │ │ ├── logger.py # Centralized logging │ │ ├── database.py # DB connection manager │ │ ├── config.py # Configuration loader │ │ └── models.py # SQLAlchemy models │ ├── services/ # Honeypot services │ │ ├── base.py # BaseHoneypotService ABC │ │ ├── ssh/ │ │ │ └── honeypot.py # SSH honeypot │ │ ├── http/ │ │ │ └── honeypot.py # HTTP honeypot │ │ └── ftp/ │ │ └── honeypot.py # FTP honeypot │ ├── ml/ # Machine Learning │ │ ├── preprocessor.py # Feature extraction │ │ ├── trainer.py # Model training │ │ └── predictor.py # Real-time classification │ ├── api/ # FastAPI application │ │ ├── main.py # FastAPI app init │ │ ├── routes/ # API endpoints │ │ └── websocket.py # Real-time feed │ └── utils/ # Utilities │ ├── geo.py # IP geolocation │ └── threat_intel.py # External API integration ├── dashboard/ # Vue.js frontend │ └── src/ ├── tests/ # Test suite │ ├── unit/ │ └── integration/ ├── config/ │ └── honeypot.yml # Main configuration ├── data/ │ ├── logs/ # Attack logs │ └── models/ # Trained ML models ├── scripts/ # Utility scripts ├── docs/ # Documentation ├── docker-compose.yml ├── Dockerfile ├── requirements.txt └── README.md

## CODING STANDARDS (MANDATORY)

### 1. Type Hints Always
```python
# ✅ GOOD
async def capture_credentials(
    username: str, 
    password: str, 
    ip: str
) -> dict[str, Any]:
    """Capture and log authentication attempt."""
    pass

# ❌ BAD
async def capture_credentials(username, password, ip):
    pass

2. Async-First Design
python

# ✅ GOOD - All I/O operations async
async def log_attack(event: AttackEvent) -> None:
    async with database.transaction():
        await database.insert(event)

# ❌ BAD - Blocking I/O
def log_attack(event: AttackEvent) -> None:
    database.insert(event)  # Blocks event loop!

3. Pydantic for Data Validation
python

from pydantic import BaseModel, Field, validator
from datetime import datetime

class AttackEvent(BaseModel):
    ip: str = Field(..., description="Attacker IP address")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    service: Literal["ssh", "http", "ftp"]
    payload: dict[str, Any] | None = None
    threat_type: str | None = None  # ML prediction
    
    @validator("ip")
    def validate_ip(cls, v: str) -> str:
        import ipaddress
        ipaddress.ip_address(v)  # Raises if invalid
        return v

4. Structured Logging
python

import structlog

logger = structlog.get_logger()

# ✅ GOOD
logger.info(
    "ssh_login_attempt",
    ip=attacker_ip,
    username=username,
    success=False,
    service="ssh"
)

# ❌ BAD
print(f"Login attempt from {attacker_ip}")

5. Comprehensive Error Handling
python

async def handle_connection(reader, writer):
    try:
        data = await asyncio.wait_for(
            reader.read(1024), 
            timeout=5.0
        )
        await process_data(data)
    except asyncio.TimeoutError:
        logger.warning("connection_timeout", ip=get_peer_ip(writer))
    except ConnectionResetError:
        logger.info("connection_reset", ip=get_peer_ip(writer))
    except Exception as e:
        logger.error("unexpected_error", exc_info=True)
        raise
    finally:
        writer.close()
        await writer.wait_closed()

6. Testing Required (80%+ Coverage)
python

import pytest

@pytest.mark.asyncio
async def test_ssh_honeypot_captures_credentials():
    """Test SSH honeypot captures username and password."""
    honeypot = SSHHoneypot(port=2222)
    
    async with honeypot:
        # Simulate attack
        result = await simulate_ssh_login(
            host="localhost",
            port=2222,
            username="admin",
            password="password123"
        )
    
    # Verify capture
    assert result.username == "admin"
    assert result.password == "password123"
    assert result.captured is True
    
    # Check database
    attack = await database.get_latest_attack()
    assert attack.service == "ssh"
    assert attack.ip == "127.0.0.1"

DATABASE SCHEMA
python

from sqlalchemy import Column, String, DateTime, JSON, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
import uuid
from datetime import datetime

Base = declarative_base()

class Attack(Base):
    """Main attack event record."""
    __tablename__ = "attacks"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip = Column(String(45), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    service = Column(String(50), nullable=False)
    payload = Column(JSON)
    threat_type = Column(String(50))  # ML classification result
    confidence = Column(Float)  # ML confidence score
    country = Column(String(2))  # ISO country code
    asn = Column(Integer)  # Autonomous System Number
    
class Session(Base):
    """Attack session lifecycle."""
    __tablename__ = "sessions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attack_id = Column(UUID(as_uuid=True), ForeignKey("attacks.id"))
    start_time = Column(DateTime(timezone=True), default=datetime.utcnow)
    end_time = Column(DateTime(timezone=True))
    commands = Column(JSON)  # Commands executed during session
    
class Credential(Base):
    """Captured credentials."""
    __tablename__ = "credentials"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attack_id = Column(UUID(as_uuid=True), ForeignKey("attacks.id"))
    username = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    success = Column(Boolean, default=False)

CONFIGURATION FORMAT
yaml

# config/honeypot.yml

services:
  ssh:
    enabled: true
    port: 2222
    host: "0.0.0.0"
    banner: "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    max_connections: 100
    timeout: 30
    
  http:
    enabled: true
    port: 8080
    host: "0.0.0.0"
    fake_cms: "WordPress 5.8"
    serve_files: true
    
  ftp:
    enabled: true
    port: 2121
    host: "0.0.0.0"
    anonymous_allowed: true

database:
  url: "${DATABASE_URL}"
  pool_size: 10
  max_overflow: 20
  echo: false

redis:
  url: "${REDIS_URL}"
  
ml:
  model_path: "data/models/threat_classifier.joblib"
  retrain_interval: "24h"
  confidence_threshold: 0.7
  features:
    - "connection_duration"
    - "payload_size"
    - "command_count"
    - "failed_auth_rate"
    
threat_intel:
  abuseipdb:
    enabled: true
    api_key: "${ABUSEIPDB_API_KEY}"
    check_on_connect: true
  virustotal:
    enabled: false
    api_key: "${VT_API_KEY}"

logging:
  level: "INFO"
  format: "json"
  output: "data/logs/tenebrinet.log"
  rotation: "100 MB"

DEVELOPMENT WORKFLOW
Phase 1: Foundation (Weeks 1-2) ← CURRENT

Goal: Core infrastructure ready

Tasks:

    ✅ Repository structure created
    ✅ Documentation and branding complete
    ⏳ Implement BaseHoneypotService abstract class
    ⏳ Design and create database schema
    ⏳ Build centralized logging system
    ⏳ Configuration management (YAML loader)
    ⏳ Testing infrastructure setup
    ⏳ CI/CD pipeline (GitHub Actions)

Phase 2: Core Services (Weeks 3-4)

    SSH honeypot with credential capture
    HTTP honeypot with fake WordPress
    FTP honeypot with fake filesystem
    Main orchestrator to run services concurrently
    Attack data collection and storage

Phase 3: ML Engine (Weeks 5-6)

    Data preprocessing pipeline
    Feature extraction (connection patterns, payload analysis)
    Model training (Random Forest, SVM)
    Real-time threat classification
    Model evaluation and tuning

Phase 4: API & Dashboard (Weeks 7-8)

    FastAPI backend with CRUD endpoints
    WebSocket real-time attack feed
    Vue.js dashboard implementation
    Attack map visualization
    Statistics and charts

Phase 5: Production (Weeks 9-10)

    Docker production configuration
    Security hardening
    Performance optimization
    Complete documentation
    Public launch preparation

CURRENT PRIORITIES

This sprint (implement in order):

    BaseHoneypotService (tenebrinet/services/base.py)
        Abstract base class for all honeypot services
        Lifecycle: start(), stop(), health_check()
        Abstract: handle_connection()
        Rate limiting integration (Redis)
        Logging interface

    Database Models (tenebrinet/core/models.py)
        SQLAlchemy models: Attack, Session, Credential
        Relationships and indexes
        Async session management

    Centralized Logger (tenebrinet/core/logger.py)
        Structured logging with structlog
        Async file writes
        JSON formatting
        Log rotation

    Configuration Loader (tenebrinet/core/config.py)
        YAML parser with Pydantic validation
        Environment variable substitution
        Configuration hot-reload support

AGENT INSTRUCTIONS
When I ask you to implement code:

DO: ✅ Generate complete, production-ready code (not snippets) ✅ Include comprehensive docstrings (Google style) ✅ Add type hints to everything ✅ Implement proper error handling ✅ Write corresponding unit tests ✅ Explain your design decisions ✅ Ask clarifying questions if requirements are ambiguous ✅ Suggest optimizations or security improvements

DON'T: ❌ Use print() for logging (use logger instead) ❌ Hardcode credentials, API keys, or secrets ❌ Skip error handling ("happy path only") ❌ Write synchronous code when async is needed ❌ Generate code without tests ❌ Use generic variable names (x, data, tmp) ❌ Ignore edge cases
Response Format

When implementing a feature, structure your response:

1. OVERVIEW
   - What you're implementing
   - Why this approach

2. CODE
   - File path and complete implementation
   - Key functions/classes highlighted

3. TESTS
   - Test file path
   - Test coverage explanation

4. DEPENDENCIES
   - New packages needed (add to requirements.txt)
   - Configuration changes

5. NEXT STEPS
   - What to implement next
   - Dependencies that need this

6. QUESTIONS
   - Clarifications needed
   - Design decisions requiring input

COMMIT MESSAGE FORMAT

Use conventional commits with emoji:

🌑 feat(ssh): implement credential capture in SSH honeypot
🐛 fix(db): resolve connection pool exhaustion under load
📝 docs: add architecture diagrams to README
♻️ refactor(ml): optimize feature preprocessing pipeline
✅ test(api): add WebSocket integration tests
🔒 security: implement rate limiting per IP
⚡️ perf: reduce attack classification latency by 40%
🎨 style: apply black formatting to services module

KEY DESIGN PRINCIPLES

    Realistic Deception
        Honeypots must be indistinguishable from real vulnerable systems
        Accurate service banners, realistic error messages
        Fake but convincing filesystems and databases

    Security-First
        Never execute attacker code directly
        Strict input validation on all data
        Proper sandboxing and isolation
        No secrets in code or logs

    High Performance
        Design for 1000+ concurrent connections
        Async I/O for everything
        Connection pooling (DB, Redis)
        Efficient ML inference (<100ms per classification)

    Observability
        Structured logging for all events
        Prometheus metrics exposure
        Health check endpoints
        Distributed tracing ready

    Modularity
        Easy to add new honeypot services
        Pluggable ML models
        Configurable threat intelligence integrations
        API-first design

EXAMPLES
Example 1: BaseHoneypotService Interface
python

from abc import ABC, abstractmethod
from typing import Any
import asyncio

class BaseHoneypotService(ABC):
    """Abstract base class for all honeypot services."""
    
    def __init__(
        self, 
        name: str, 
        port: int, 
        host: str = "0.0.0.0"
    ) -> None:
        self.name = name
        self.port = port
        self.host = host
        self.server: asyncio.Server | None = None
        self._running = False
    
    async def start(self) -> None:
        """Start the honeypot service."""
        logger.info(f"{self.name}_starting", port=self.port)
        self.server = await asyncio.start_server(
            self.handle_connection,
            self.host,
            self.port
        )
        self._running = True
        logger.info(f"{self.name}_started", port=self.port)
    
    async def stop(self) -> None:
        """Stop the honeypot service."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self._running = False
        logger.info(f"{self.name}_stopped")
    
    @abstractmethod
    async def handle_connection(
        self, 
        reader: asyncio.StreamReader, 
        writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming connection. Must be implemented by subclasses."""
        pass
    
    async def health_check(self) -> dict[str, Any]:
        """Return service health status."""
        return {
            "service": self.name,
            "running": self._running,
            "port": self.port
        }

Example 2: Attack Event Logging
python

async def log_attack_event(
    ip: str,
    service: str,
    payload: dict[str, Any],
    threat_type: str | None = None
) -> UUID:
    """Log attack event to database.
    
    Args:
        ip: Attacker IP address
        service: Target service (ssh, http, ftp)
        payload: Attack data
        threat_type: ML classification result
        
    Returns:
        UUID of created attack record
    """
    # Enrich with geolocation
    geo_data = await get_ip_geolocation(ip)
    
    # Create attack record
    attack = Attack(
        ip=ip,
        service=service,
        payload=payload,
        threat_type=threat_type,
        country=geo_data.get("country_code"),
        asn=geo_data.get("asn")
    )
    
    # Save to database
    async with database.transaction() as session:
        session.add(attack)
        await session.commit()
        await session.refresh(attack)
    
    # Log structured event
    logger.info(
        "attack_logged",
        attack_id=str(attack.id),
        ip=ip,
        service=service,
        threat_type=threat_type
    )
    
    return attack.id

BRAND IDENTITY

Colors:

    Primary: #1a0033 (Deep purple-black)
    Secondary: #7b2cbf (Royal purple)
    Accent: #00ff9f (Neon mint - for alerts/highlights)
    Background: #0d0221 (Near black)
    Text: #e0e0e0 (Soft white)

Tone:

    Professional but edgy
    Security-focused
    "Dark mode hacker aesthetic"
    Production-ready, not toy project

ASCII Logo (for terminal):

████████╗███████╗███╗   ██╗███████╗██████╗ ██████╗ ██╗███╗   ██╗███████╗████████╗
╚══██╔══╝██╔════╝████╗  ██║██╔════╝██╔══██╗██╔══██╗██║████╗  ██║██╔════╝╚══██╔══╝
   ██║   █████╗  ██╔██╗ ██║█████╗  ██████╔╝██████╔╝██║██╔██╗ ██║█████╗     ██║   
   ██║   ██╔══╝  ██║╚██╗██║██╔══╝  ██╔══██╗██╔══██╗██║██║╚██╗██║██╔══╝     ██║   
   ██║   ███████╗██║ ╚████║███████╗██████╔╝██║  ██║██║██║ ╚████║███████╗   ██║   
   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   
   
   🌑 Where darkness meets defense

READY STATE CONFIRMATION

Before we start coding, confirm you understand:

    ✅ TenebriNET is an intelligent honeypot that captures and classifies cyber attacks
    ✅ Stack: Python async + FastAPI + PostgreSQL + Redis + scikit-learn + Vue.js
    ✅ Current phase: Foundation (BaseHoneypotService, DB schema, logging, config)
    ✅ All code must be: typed, async, tested, documented, production-ready
    ✅ You will ask questions when requirements are unclear
    ✅ You will suggest improvements when you see opportunities

Let's capture what hides in the dark. 🌑💜 CONTEXT_EOF

echo "✅ .codex-context.md created!"

---

# 🚀 VERIFICACIÓN Y USO

### **1. Verificar que se creó correctamente:**
```bash
ls -lah .codex-context.md
cat .codex-context.md | head -20

2. Iniciar Codex con el contexto:
bash

# Opción A: Cargar al iniciar
codex --context .codex-context.md

# Opción B: Si tu Codex usa otro flag
codex --load .codex-context.md
codex -c .codex-context.md
codex --file .codex-context.md

3. Si no soporta flag, cargarlo manualmente:
bash

# Inicia Codex
codex

# Dentro de la sesión, intenta:
/load .codex-context.md
# o
@context .codex-context.md
# o
!load .codex-context.md

4. Si nada funciona, copy-paste directo:
bash

codex

# Primera interacción - pega:
"""
[Abre .codex-context.md y copia TODO el contenido aquí]

Confirm you've loaded the context and are ready to build TenebriNET.
"""

✅ PRUEBA DE VERIFICACIÓN

Una vez cargado el contexto, haz esta prueba:
bash

> What are we building and what's the current priority?

Respuesta esperada del agente:

We're building TenebriNET, an ML-powered honeypot infrastructure.

Current Phase: Foundation (Weeks 1-2)
Priority tasks:
1. BaseHoneypotService abstract class (services/base.py)
2. Database schema with SQLAlchemy models
3. Centralized logging system
4. Configuration loader from YAML

Tech stack: Python 3.11+ async, FastAPI, PostgreSQL, Redis, scikit-learn

Ready to start with BaseHoneypotService implementation?

🎯 PRIMERA TAREA RECOMENDADA

Después de verificar que el contexto cargó:
bash

> Implement the BaseHoneypotService abstract class in tenebrinet/services/base.py following the architecture described in the context. Include lifecycle management, rate limiting, and comprehensive tests.
