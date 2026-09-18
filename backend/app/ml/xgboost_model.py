"""XGBoost Classifier for VPN Protocol Security Assessment."""
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
import xgboost as xgb

logger = logging.getLogger(__name__)


class VPNXGBoostClassifier:
    """Supervised XGBoost Classifier trained on labeled VPN handshake flow features."""

    def __init__(self, model_path: Optional[Union[str, Path]] = None):
        self.model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.08,
            subsample=0.85,
            colsample_bytree=0.85,
            eval_metric="logloss",
            random_state=42,
        )
        self.is_trained = False
        self.metrics: Dict[str, Any] = {}
        self.model_path = Path(model_path) if model_path else None

        if self.model_path and self.model_path.exists():
            self.load(self.model_path)

    def train(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> Dict[str, Any]:
        """Train XGBoost model and compute validation metrics."""
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        logger.info(f"Training XGBoost classifier on {len(X_train)} samples...")
        self.model.fit(X_train, y_train)
        self.is_trained = True

        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)[:, 1]

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        self.metrics = {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "precision": float(precision_score(y_test, y_pred, zero_division=0)),
            "recall": float(recall_score(y_test, y_pred, zero_division=0)),
            "f1": float(f1_score(y_test, y_pred, zero_division=0)),
            "false_positive_rate": float(fpr),
            "confusion_matrix": {
                "true_negatives": int(tn),
                "false_positives": int(fp),
                "false_negatives": int(fn),
                "true_positives": int(tp),
            },
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
        }

        logger.info(
            f"XGBoost Training Complete. Accuracy: {self.metrics['accuracy']:.4f}, "
            f"Precision: {self.metrics['precision']:.4f}, Recall: {self.metrics['recall']:.4f}, "
            f"FPR: {self.metrics['false_positive_rate']:.4f}"
        )
        return self.metrics

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return class probability distributions [P(safe), P(vulnerable)]."""
        if not self.is_trained:
            raise RuntimeError("Model is not trained yet.")
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self.model.predict_proba(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return binary prediction: 1 = Vulnerable / High Risk, 0 = Secure."""
        if not self.is_trained:
            raise RuntimeError("Model is not trained yet.")
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self.model.predict(X)

    def save(self, save_path: Union[str, Path]) -> None:
        """Save model weights and training metrics."""
        path = Path(save_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.model.save_model(str(path))

        meta_path = path.parent / f"{path.stem}_metrics.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(self.metrics, f, indent=2)
        logger.info(f"Saved XGBoost model to {path} and metrics to {meta_path}")

    def load(self, load_path: Union[str, Path]) -> None:
        """Load pre-trained model weights and metrics."""
        path = Path(load_path)
        if path.exists():
            self.model.load_model(str(path))
            self.is_trained = True

            meta_path = path.parent / f"{path.stem}_metrics.json"
            if meta_path.exists():
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        self.metrics = json.load(f)
                except Exception:
                    pass
            logger.info(f"Loaded XGBoost model from {path}")
