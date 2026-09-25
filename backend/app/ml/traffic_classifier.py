"""Supervised Encrypted Traffic Classifier for NetSentry.ai.
Classifies ESP flows into 8 behavioral categories using 14 flow-level statistical features.
"""
from dataclasses import dataclass
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

from app.ml.flow_features import FLOW_FEATURE_NAMES, extract_14_flow_features, flow_stats_to_vector
from app.testbed.traffic_generator import VPNTrafficProfileGenerator

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parent / "saved_models"
CLASSIFIER_PATH = MODELS_DIR / "traffic_classifier.joblib"
METRICS_PATH = MODELS_DIR / "traffic_classifier_metrics.json"

TRAFFIC_CLASSES = [
    "Web",
    "VoIP",
    "Video",
    "Messaging-like",
    "Email-like",
    "ICMP",
    "Bulk/Data",
    "Unknown",
]


@dataclass
class TrafficClassificationResult:
    predicted_class: str
    confidence: float
    probabilities: Dict[str, float]
    top_behavioral_indicators: List[str]
    features_extracted: Dict[str, float]

    @property
    def predicted_application(self) -> str:
        return self.predicted_class

    @property
    def behavioral_indicators(self) -> List[str]:
        return self.top_behavioral_indicators

    @property
    def risk_level(self) -> str:
        if self.predicted_class in ("Bulk/Data", "Unknown"):
            return "HIGH"
        elif self.predicted_class in ("Messaging-like", "VoIP"):
            return "MEDIUM"
        return "LOW"

    def dict(self) -> Dict[str, Any]:
        return {
            "predicted_class": self.predicted_class,
            "predicted_application": self.predicted_class,
            "confidence": self.confidence,
            "probabilities": self.probabilities,
            "top_behavioral_indicators": self.top_behavioral_indicators,
            "behavioral_indicators": self.top_behavioral_indicators,
            "risk_level": self.risk_level,
            "features_extracted": self.features_extracted,
        }


ClassificationResult = TrafficClassificationResult



class VPNEncryptedTrafficClassifier:
    """Classifies encrypted ESP network flows based on behavioral metadata."""

    _instance: Optional["VPNEncryptedTrafficClassifier"] = None

    def __init__(self, model_path: Optional[Path] = CLASSIFIER_PATH, auto_train: bool = True):
        self.model_path = model_path
        self.model: Optional[RandomForestClassifier] = None
        self.metrics: Dict[str, Any] = {}
        self.classes: List[str] = [c for c in TRAFFIC_CLASSES if c != "Unknown"]

        if model_path and model_path.exists():
            self.load(model_path)
        elif auto_train:
            self.train_and_save()

    @classmethod
    def get_instance(cls) -> "VPNEncryptedTrafficClassifier":
        """Singleton accessor for efficient reuse."""
        if cls._instance is None:
            cls._instance = VPNEncryptedTrafficClassifier()
        return cls._instance

    def _generate_synthetic_training_data(self, samples_per_class: int = 150) -> Tuple[np.ndarray, np.ndarray]:
        """Synthesize training data across behavioral profiles."""
        X_list = []
        y_list = []

        for class_idx, class_name in enumerate(self.classes):
            for _ in range(samples_per_class):
                n_pkts = int(np.random.randint(15, 120))
                profile = VPNTrafficProfileGenerator.generate_flow(
                    traffic_type=class_name,
                    num_packets=n_pkts,
                )
                vec = flow_stats_to_vector(profile.stats)
                X_list.append(vec)
                y_list.append(class_idx)

        return np.vstack(X_list), np.array(y_list, dtype=np.int32)

    def train_and_save(self) -> Dict[str, Any]:
        """Fit model, evaluate metrics out-of-sample, and save weights."""
        logger.info("Generating synthetic behavioral traffic dataset for training...")
        X, y = self._generate_synthetic_training_data(samples_per_class=120)

        # 80/20 train/test split ensuring stratified distribution
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )

        clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            random_state=42,
            n_jobs=-1,
        )
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)
        acc = float(accuracy_score(y_test, y_pred))
        p, r, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted", zero_division=0)
        c_matrix = confusion_matrix(y_test, y_pred).tolist()

        feature_importances = {
            name: round(float(imp), 4)
            for name, imp in zip(FLOW_FEATURE_NAMES, clf.feature_importances_)
        }

        metrics = {
            "accuracy": round(acc, 4),
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": c_matrix,
            "classes": self.classes,
            "feature_importances": feature_importances,
            "samples_trained": int(len(X_train)),
            "samples_tested": int(len(X_test)),
        }

        self.model = clf
        self.metrics = metrics

        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        if self.model_path:
            joblib.dump(clf, self.model_path)
            with open(METRICS_PATH, "w", encoding="utf-8") as f:
                json.dump(metrics, f, indent=2)
            logger.info(f"Traffic classifier saved to {self.model_path} with {acc * 100:.1f}% test accuracy.")

        return metrics

    def load(self, model_path: Path) -> None:
        """Load trained model weights."""
        try:
            self.model = joblib.load(model_path)
            if METRICS_PATH.exists():
                with open(METRICS_PATH, "r", encoding="utf-8") as f:
                    self.metrics = json.load(f)
            logger.info("Loaded traffic classifier model.")
        except Exception as e:
            logger.warning(f"Failed to load traffic classifier: {e}. Retraining...")
            self.train_and_save()

    def classify(self, feat_vec: Any) -> TrafficClassificationResult:
        """Classify a 14-dimensional flow feature vector (np.ndarray or list)."""
        arr = np.asarray(feat_vec, dtype=np.float32)
        return self.classify_vector(arr)

    def classify_vector(self, feat_vec: np.ndarray) -> TrafficClassificationResult:
        """Classify a 14-dimensional flow feature vector."""
        if self.model is None:
            self.train_and_save()

        # Handle degenerate/low-volume flows
        pkt_count = feat_vec[0]
        if pkt_count < 3:
            return TrafficClassificationResult(
                predicted_class="Unknown",
                confidence=0.50,
                probabilities={c: 0.0 for c in TRAFFIC_CLASSES},
                top_behavioral_indicators=["Flow contains fewer than 3 packets; insufficient statistics for behavioral classification."],
                features_extracted={name: float(val) for name, val in zip(FLOW_FEATURE_NAMES, feat_vec)},
            )

        X = feat_vec.reshape(1, -1)
        probs = self.model.predict_proba(X)[0]
        max_idx = int(np.argmax(probs))
        max_prob = float(probs[max_idx])
        pred_class = self.classes[max_idx]

        # Unknown threshold if model is not confident
        if max_prob < 0.40:
            pred_class = "Unknown"

        # Generate human-readable behavioral indicators from top features
        indicators = []
        mean_sz = feat_vec[FLOW_FEATURE_NAMES.index("mean_packet_size")]
        ratio = feat_vec[FLOW_FEATURE_NAMES.index("downlink_uplink_ratio")]
        pps = feat_vec[FLOW_FEATURE_NAMES.index("packets_per_sec")]
        mean_iat = feat_vec[FLOW_FEATURE_NAMES.index("mean_inter_arrival_time")]

        if pred_class == "VoIP":
            indicators.append(f"Near-symmetric payload size ({mean_sz:.0f} bytes) characteristic of voice codecs")
            indicators.append(f"Consistent low inter-arrival delta ({mean_iat * 1000:.1f}ms) matching audio framing")
        elif pred_class == "Video":
            indicators.append(f"Heavy asymmetric downlink bias ({ratio:.1f}x downlink:uplink ratio)")
            indicators.append(f"High average packet payload size ({mean_sz:.0f} bytes) near Ethernet MTU")
        elif pred_class == "Web":
            indicators.append(f"Bursty packet rate ({pps:.1f} packets/sec) with variable response lengths")
            indicators.append(f"Moderate downlink:uplink ratio ({ratio:.1f}x) matching web asset downloads")
        elif pred_class == "Messaging-like":
            indicators.append(f"Small intermittent payloads ({mean_sz:.0f} bytes) followed by idle periods")
        elif pred_class == "Bulk/Data":
            indicators.append(f"Sustained high-throughput transfer near maximum payload limits")
        elif pred_class == "ICMP":
            indicators.append(f"Strict periodic ping timing (~1s interval) and small uniform packet sizes")
        else:
            indicators.append(f"Observed packet rate: {pps:.1f} pps, mean size: {mean_sz:.0f} bytes")

        prob_dict = {cls_name: round(float(p), 4) for cls_name, p in zip(self.classes, probs)}
        feat_dict = {name: round(float(val), 2) for name, val in zip(FLOW_FEATURE_NAMES, feat_vec)}

        return TrafficClassificationResult(
            predicted_class=pred_class,
            confidence=round(max_prob, 4),
            probabilities=prob_dict,
            top_behavioral_indicators=indicators,
            features_extracted=feat_dict,
        )

    def classify_packets(self, packets: List[Dict[str, Any]], client_ip: Optional[str] = None) -> TrafficClassificationResult:
        """Classify a list of raw packet records directly."""
        feat_vec = extract_14_flow_features(packets, client_ip=client_ip)
        return self.classify_vector(feat_vec)
