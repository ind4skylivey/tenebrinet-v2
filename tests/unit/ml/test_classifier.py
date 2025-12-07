# tests/unit/ml/test_classifier.py
"""
Unit tests for ML classifier and feature extraction.
"""
import os
import pytest
import tempfile
from typing import List, Dict, Any

from tenebrinet.ml.classifier import ThreatClassifier
from tenebrinet.ml.features import FeatureExtractor


@pytest.fixture
def sample_data() -> List[Dict[str, Any]]:
    """Create sample attack data for training/testing."""
    return [
        {
            "service": "http",
            "timestamp": "2024-12-07T12:00:00Z",
            "payload": {
                "method": "GET",
                "path": "/wp-login.php",
                "query": "user=admin&pass=' OR '1'='1",
                "user_agent": "Mozilla/5.0 sqlmap/1.0"
            }
        },
        {
            "service": "ssh",
            "timestamp": "2024-12-07T13:00:00Z",
            "payload": {
                "username": "root",
                "password": "password123"
            }
        },
        {
            "service": "http",
            "timestamp": "2024-12-07T14:00:00Z",
            "payload": {
                "method": "GET",
                "path": "/etc/passwd",
                "user_agent": "curl/7.68.0"
            }
        }
    ]


@pytest.fixture
def sample_labels() -> List[str]:
    """Create sample labels corresponding to data."""
    return ["sql_injection", "credential_attack", "path_traversal"]


class TestFeatureExtractor:
    """Tests for FeatureExtractor."""

    def test_fit_transform(self, sample_data):
        """Test feature extraction pipeline."""
        extractor = FeatureExtractor()
        features = extractor.fit_transform(sample_data)

        # Check output shape
        assert features.shape[0] == len(sample_data)
        assert features.shape[1] > 0

        # Check if fitted
        assert extractor._is_fitted is True

    def test_feature_extraction_logic(self):
        """Test specific feature extraction logic."""
        extractor = FeatureExtractor()
        data = [{
            "service": "http",
            "payload": {
                "path": "/wp-login.php",
                "user_agent": "sqlmap"
            }
        }]

        df = extractor._preprocess(data)

        assert df.iloc[0]["is_scanner"] == 1
        assert df.iloc[0]["service"] == "http"


class TestThreatClassifier:
    """Tests for ThreatClassifier."""

    def test_train_predict(self, sample_data, sample_labels):
        """Test training and prediction flow."""
        classifier = ThreatClassifier()

        # Train
        metrics = classifier.train(sample_data, sample_labels)
        assert "accuracy" in metrics
        assert metrics["accuracy"] > 0.0

        # Predict
        preds, confs = classifier.predict(sample_data)
        assert len(preds) == len(sample_data)
        assert len(confs) == len(sample_data)
        assert all(isinstance(c, float) for c in confs)

    def test_save_load(self, sample_data, sample_labels):
        """Test model persistence."""
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp:
            model_path = tmp.name

        try:
            # Train and save
            classifier = ThreatClassifier(model_path=model_path)
            classifier.train(sample_data, sample_labels)
            classifier.save()

            assert os.path.exists(model_path)

            # Load new instance
            new_classifier = ThreatClassifier(model_path=model_path)
            new_classifier.load()

            # Verify it can predict
            preds, _ = new_classifier.predict(sample_data)
            assert len(preds) == len(sample_data)

        finally:
            if os.path.exists(model_path):
                os.unlink(model_path)
