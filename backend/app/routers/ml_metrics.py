"""ML Model Performance & Explainability API Router."""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth import get_current_user
from app.models import User
from app.ml.ensemble import MLEnsemble

router = APIRouter(prefix="/ml", tags=["Machine Learning"])


class MLMetricsResponse(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    confusion_matrix: Dict[str, int]
    train_samples: int
    test_samples: int


class MLSamplePredictRequest(BaseModel):
    ike_version: int = 2
    dh_group_num: Optional[int] = 14
    dh_group: Optional[str] = "Group 14 (2048-bit)"
    cipher: Optional[str] = "AES-GCM-256"
    integrity_algo: Optional[str] = "AUTH_HMAC_SHA2_256_128"
    prf_algo: Optional[str] = "PRF_HMAC_SHA2_256"
    exchange_types: List[str] = ["IKE_SA_INIT", "IKE_AUTH"]
    packet_count: int = 4
    esp_packets: int = 150
    pfs_enabled: bool = True
    auth_method: Optional[str] = "RSA Digital Signatures"


@router.get(
    "/metrics",
    response_model=MLMetricsResponse,
    summary="Get model validation metrics, accuracy, precision, recall, and confusion matrix"
)
async def get_ml_metrics(current_user: User = Depends(get_current_user)):
    """Return model performance metrics validated against the labeled testbed."""
    ensemble = MLEnsemble.get_instance()
    metrics = ensemble.get_metrics()
    return metrics


@router.post(
    "/predict",
    summary="Interactive ML prediction and SHAP explanation for a session signature"
)
async def predict_ml_session(
    payload: MLSamplePredictRequest,
    current_user: User = Depends(get_current_user),
):
    """Evaluate session parameters using the XGBoost + Isolation Forest ensemble with SHAP explanation."""
    ensemble = MLEnsemble.get_instance()
    verdict = ensemble.analyze_session(payload.model_dump())
    return {
        "is_vulnerable": verdict.is_vulnerable,
        "vulnerability_probability": verdict.vulnerability_probability,
        "is_anomaly": verdict.is_anomaly,
        "anomaly_score": verdict.anomaly_score,
        "top_shap_features": verdict.shap_explanations,
        "feature_vector": verdict.feature_vector,
    }
