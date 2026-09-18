"""Isolation Forest Anomaly Detector for novel and zero-day VPN flow deviations."""
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Union
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)


class VPNIsolationForest:
    """Unsupervised Isolation Forest for detecting novel/unseen handshake and flow anomalies."""

    def __init__(self, contamination: float = 0.1, model_path: Optional[Union[str, Path]] = None):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        self.is_trained = False
        self.model_path = Path(model_path) if model_path else None

        if self.model_path and self.model_path.exists():
            self.load(self.model_path)

    def train(self, X: np.ndarray) -> None:
        """Fit the Isolation Forest model on flow features."""
        logger.info(f"Training Isolation Forest on {len(X)} samples...")
        self.model.fit(X)
        self.is_trained = True
        logger.info("Isolation Forest training complete.")

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomaly labels:
        1 = Normal / In-Distribution
        -1 = Anomaly / Outlier
        """
        if not self.is_trained:
            raise RuntimeError("Model is not trained yet.")
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self.model.predict(X)

    def score_anomaly(self, X: np.ndarray) -> float:
        """
        Compute an explainable anomaly score scaled between 0.0 and 1.0:
        0.0 = completely normal / in-distribution
        1.0 = highly anomalous / severe deviation
        """
        if not self.is_trained:
            raise RuntimeError("Model is not trained yet.")
        if X.ndim == 1:
            X = X.reshape(1, -1)

        # score_samples returns opposite of anomaly score (lower is more anomalous)
        raw_score = self.model.score_samples(X)[0]
        # raw_score typically falls in [-0.8, -0.3] for anomalies and [-0.5, -0.2] for normal
        # Map into standard 0.0 - 1.0 range
        scaled_score = float(np.clip(( -raw_score - 0.35 ) / 0.45, 0.0, 1.0))
        return round(scaled_score, 4)

    def save(self, save_path: Union[str, Path]) -> None:
        """Serialize model to disk."""
        path = Path(save_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, path)
        logger.info(f"Saved Isolation Forest to {path}")

    def load(self, load_path: Union[str, Path]) -> None:
        """Load serialized model from disk."""
        path = Path(load_path)
        if path.exists():
            self.model = joblib.load(path)
            self.is_trained = True
            logger.info(f"Loaded Isolation Forest from {path}")
