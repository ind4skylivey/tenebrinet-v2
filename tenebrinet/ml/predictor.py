# tenebrinet/ml/predictor.py
"""
Threat Predictor service.

High-level interface for making threat predictions using the trained model.
"""
import os
from typing import Any, Dict, Optional, Tuple

import structlog

from tenebrinet.core.config import MLConfig
from tenebrinet.ml.classifier import ThreatClassifier


logger = structlog.get_logger()


class ThreatPredictor:
    """
    Service for predicting threat types.
    """

    def __init__(self, config: MLConfig) -> None:
        self.config = config
        self.classifier = ThreatClassifier(model_path=config.model_path)
        self._is_ready = False
        self._load_model()

    def _load_model(self) -> None:
        """Attempt to load the pre-trained model."""
        try:
            if os.path.exists(self.config.model_path):
                self.classifier.load()
                self._is_ready = True
                logger.info("ml_model_loaded", path=self.config.model_path)
            else:
                logger.warning(
                    "ml_model_not_found",
                    path=self.config.model_path,
                    msg="Predictions will be unavailable until model is trained"
                )
        except Exception as e:
            logger.error("ml_model_load_failed", error=str(e))

    def predict_one(self, attack_data: Dict[str, Any]) -> Tuple[Optional[str], float]:
        """
        Predict threat type for a single attack.

        Args:
            attack_data: Dictionary containing attack details.

        Returns:
            Tuple of (predicted_threat_type, confidence).
            Returns (None, 0.0) if model is not ready or prediction fails.
        """
        if not self._is_ready:
            return None, 0.0

        try:
            predictions, confidences = self.classifier.predict([attack_data])
            confidence = confidences[0]

            # Filter by confidence threshold
            if confidence < self.config.confidence_threshold:
                return "unknown", confidence

            return predictions[0], confidence

        except Exception as e:
            logger.error("ml_prediction_failed", error=str(e))
            return None, 0.0

    @property
    def is_ready(self) -> bool:
        """Check if the model is loaded and ready."""
        return self._is_ready
