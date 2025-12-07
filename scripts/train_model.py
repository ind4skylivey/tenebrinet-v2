# scripts/train_model.py
"""
Script to train the ML threat classifier from database records.
"""
import asyncio
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

import structlog  # noqa: E402
from sqlalchemy import select  # noqa: E402

from tenebrinet.core.config import load_config  # noqa: E402
from tenebrinet.core.database import AsyncSessionLocal  # noqa: E402
from tenebrinet.core.models import Attack  # noqa: E402
from tenebrinet.ml.classifier import ThreatClassifier  # noqa: E402

logger = structlog.get_logger()


async def train():
    """Train the model using data from the database."""
    config = load_config("config/honeypot.yml")

    logger.info("ml_training_started")

    # Fetch data
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Attack).where(Attack.threat_type.is_not(None))
        )
        attacks = result.scalars().all()

    if not attacks:
        logger.error(
            "ml_training_no_data",
            msg="No labeled attacks found in database"
        )
        return

    logger.info("ml_data_loaded", count=len(attacks))

    # Prepare data
    X = []
    y = []

    for attack in attacks:
        # Convert model to dict-like structure expected by extractor
        attack_dict = {
            "service": attack.service,
            "timestamp": attack.timestamp,
            "payload": attack.payload
        }
        X.append(attack_dict)
        y.append(attack.threat_type)

    # Train model
    classifier = ThreatClassifier(model_path=config.ml.model_path)
    metrics = classifier.train(X, y)

    logger.info("ml_training_complete", accuracy=metrics["accuracy"])

    # Save model
    classifier.save()
    logger.info("ml_model_saved", path=config.ml.model_path)


if __name__ == "__main__":
    try:
        asyncio.run(train())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error("ml_training_failed", error=str(e))
        sys.exit(1)
