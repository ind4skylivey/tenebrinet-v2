# tenebrinet/ml/features.py
"""
Feature extraction for TenebriNET ML pipeline.

Converts raw attack data into numerical features for model training and inference.
"""
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer


class FeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts features from raw attack dictionaries.
    """

    def __init__(self) -> None:
        self.pipeline: Optional[Pipeline] = None
        self._is_fitted = False

    def fit(self, X: List[Dict[str, Any]], y: Any = None) -> "FeatureExtractor":
        """
        Fit the feature extractor to the data.

        Args:
            X: List of attack dictionaries.
            y: Ignored.
        """
        df = self._preprocess(X)

        # Define transformers
        numeric_features = [
            "payload_len", "hour", "is_scanner",
            "sqli_keywords", "xss_keywords", "path_traversal_keywords"
        ]
        categorical_features = ["service", "method"]

        numeric_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='constant', fill_value=0)),
            ('scaler', StandardScaler())
        ])

        categorical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='constant', fill_value='unknown')),
            ('onehot', OneHotEncoder(handle_unknown='ignore'))
        ])

        self.pipeline = ColumnTransformer(
            transformers=[
                ('num', numeric_transformer, numeric_features),
                ('cat', categorical_transformer, categorical_features)
            ]
        )

        self.pipeline.fit(df)
        self._is_fitted = True
        return self

    def transform(self, X: List[Dict[str, Any]]) -> np.ndarray:
        """
        Transform raw data into feature matrix.
        """
        if not self._is_fitted or self.pipeline is None:
            raise RuntimeError("FeatureExtractor must be fitted before transform")

        df = self._preprocess(X)
        return self.pipeline.transform(df)

    def _preprocess(self, data: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Convert list of dicts to DataFrame and extract basic features.
        """
        processed_data = []

        for item in data:
            payload = item.get("payload", {}) or {}
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError:
                    payload = {}

            # Extract basic fields
            timestamp = item.get("timestamp")
            if isinstance(timestamp, str):
                try:
                    dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    hour = dt.hour
                except ValueError:
                    hour = 0
            elif isinstance(timestamp, datetime):
                hour = timestamp.hour
            else:
                hour = 0

            # Payload analysis
            payload_str = str(payload).lower()

            # Keyword counting
            sqli_keywords = len(re.findall(r"(union|select|insert|drop|update|where|from)", payload_str))
            xss_keywords = len(re.findall(r"(script|alert|onload|onerror|img|svg|iframe)", payload_str))
            path_traversal_keywords = len(re.findall(r"(\.\./|\.\.\\|/etc/passwd|c:\\windows)", payload_str))

            # User Agent analysis
            user_agent = payload.get("user_agent", "").lower() if isinstance(payload, dict) else ""
            is_scanner = 1 if any(s in user_agent for s in ["nmap", "nikto", "sqlmap", "curl", "python"]) else 0

            processed_data.append({
                "service": item.get("service", "unknown"),
                "method": payload.get("method", "unknown") if isinstance(payload, dict) else "unknown",
                "payload_len": len(payload_str),
                "hour": hour,
                "is_scanner": is_scanner,
                "sqli_keywords": sqli_keywords,
                "xss_keywords": xss_keywords,
                "path_traversal_keywords": path_traversal_keywords,
            })

        return pd.DataFrame(processed_data)
