# tenebrinet/ml/classifier.py
"""
Threat Classifier model wrapper.

Wraps scikit-learn models for training and inference.
"""
import joblib
import os
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.base import BaseEstimator

from tenebrinet.ml.features import FeatureExtractor


class ThreatClassifier:
    """
    ML model for classifying attack types.
    """

    def __init__(self, model_path: Optional[str] = None) -> None:
        self.model_path = model_path
        self.feature_extractor = FeatureExtractor()
        self.model: Optional[BaseEstimator] = None
        self.classes_: Optional[np.ndarray] = None

    def train(self, X_raw: List[Dict[str, Any]], y: List[str]) -> Dict[str, float]:
        """
        Train the model on raw data.

        Args:
            X_raw: List of attack dictionaries.
            y: List of target labels (threat types).

        Returns:
            Dictionary of training metrics.
        """
        # Feature extraction
        X = self.feature_extractor.fit_transform(X_raw)

        # Initialize and train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight="balanced"
        )
        self.model.fit(X, y)
        self.classes_ = self.model.classes_

        # Calculate basic accuracy on training set
        score = self.model.score(X, y)

        return {"accuracy": score}

    def predict(self, X_raw: List[Dict[str, Any]]) -> Tuple[List[str], List[float]]:
        """
        Predict threat types for new data.

        Args:
            X_raw: List of attack dictionaries.

        Returns:
            Tuple of (predicted_labels, confidences).
        """
        if self.model is None:
            raise RuntimeError("Model not trained or loaded")

        X = self.feature_extractor.transform(X_raw)

        # Get probabilities
        probas = self.model.predict_proba(X)

        # Get max probability and corresponding class
        max_probas_indices = np.argmax(probas, axis=1)
        confidences = np.max(probas, axis=1)
        predictions = self.classes_[max_probas_indices]

        return predictions.tolist(), confidences.tolist()

    def save(self, path: Optional[str] = None) -> None:
        """Save the model and feature extractor to disk."""
        save_path = path or self.model_path
        if not save_path:
            raise ValueError("No model path specified")

        # Ensure directory exists
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        joblib.dump({
            "model": self.model,
            "feature_extractor": self.feature_extractor,
            "classes": self.classes_
        }, save_path)

    def load(self, path: Optional[str] = None) -> None:
        """Load the model and feature extractor from disk."""
        load_path = path or self.model_path
        if not load_path or not os.path.exists(load_path):
            raise FileNotFoundError(f"Model file not found: {load_path}")

        data = joblib.load(load_path)
        self.model = data["model"]
        self.feature_extractor = data["feature_extractor"]
        self.classes_ = data["classes"]
