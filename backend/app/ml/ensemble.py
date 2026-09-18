"""Unified ML Detection Ensemble: XGBoost + Isolation Forest + SHAP Explainability."""
from dataclasses import dataclass
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np

from app.ml.dataset import generate_labeled_vpn_dataset
from app.ml.features import extract_features_from_session
from app.ml.isolation_forest import VPNIsolationForest
from app.ml.shap_explain import SHAPExplainer
from app.ml.xgboost_model import VPNXGBoostClassifier

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parent / "saved_models"


@dataclass
class MLEnsembleVerdict:
    """Unified assessment output from the ML detection ensemble."""
    is_vulnerable: bool
    vulnerability_probability: float
    is_anomaly: bool
    anomaly_score: float
    shap_explanations: List[Dict[str, Any]]
    feature_vector: List[float]


class MLEnsemble:
    """Coordinates XGBoost classifier, Isolation Forest, and SHAP explanations."""

    _instance: Optional["MLEnsemble"] = None

    def __init__(self, auto_train: bool = True):
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        self.xgb_path = MODELS_DIR / "xgboost_model.ubj"
        self.iso_path = MODELS_DIR / "isolation_forest.joblib"

        self.xgb = VPNXGBoostClassifier(self.xgb_path if self.xgb_path.exists() else None)
        self.iso = VPNIsolationForest(contamination=0.1, model_path=self.iso_path if self.iso_path.exists() else None)
        self.shap: Optional[SHAPExplainer] = None

        if not (self.xgb.is_trained and self.iso.is_trained) and auto_train:
            self.train_all()
        elif self.xgb.is_trained:
            self.shap = SHAPExplainer(self.xgb.model)

    @classmethod
    def get_instance(cls) -> "MLEnsemble":
        """Singleton accessor for efficient reuse of model weights across requests."""
        if cls._instance is None:
            cls._instance = MLEnsemble()
        return cls._instance

    def train_all(self) -> Dict[str, Any]:
        """Generate training dataset, fit both models, compute SHAP, and persist weights."""
        logger.info("Generating labeled VPN testbed dataset for model training...")
        X, y = generate_labeled_vpn_dataset()

        logger.info("Fitting supervised XGBoost classifier...")
        xgb_metrics = self.xgb.train(X, y)
        self.xgb.save(self.xgb_path)

        logger.info("Fitting unsupervised Isolation Forest on secure baselines...")
        # Fit Isolation Forest primarily on benign traffic to learn standard profile
        X_benign = X[y == 0]
        self.iso.train(X_benign)
        self.iso.save(self.iso_path)

        logger.info("Initializing SHAP TreeExplainer...")
        self.shap = SHAPExplainer(self.xgb.model)

        return xgb_metrics

    def analyze_session(self, session_data: Any) -> MLEnsembleVerdict:
        """Run complete ML ensemble pipeline on a single VPN session."""
        feat_vec = extract_features_from_session(session_data)

        # 1. Primary: XGBoost prediction
        prob_vulnerable = float(self.xgb.predict_proba(feat_vec)[0, 1])
        is_vuln = bool(prob_vulnerable >= 0.50)

        # 2. Secondary: Isolation Forest anomaly score
        anomaly_score = self.iso.score_anomaly(feat_vec)
        is_anomaly = bool(anomaly_score >= 0.65 or self.iso.predict(feat_vec)[0] == -1)

        # 3. Explainability: SHAP feature attribution
        shap_attribs: List[Dict[str, Any]] = []
        if self.shap:
            shap_attribs = self.shap.explain_session(feat_vec, top_n=4)

        return MLEnsembleVerdict(
            is_vulnerable=is_vuln,
            vulnerability_probability=round(prob_vulnerable, 4),
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            shap_explanations=shap_attribs,
            feature_vector=[round(float(v), 2) for v in feat_vec],
        )

    def get_metrics(self) -> Dict[str, Any]:
        """Return headline accuracy, precision, recall, and false positive rate."""
        return self.xgb.metrics
