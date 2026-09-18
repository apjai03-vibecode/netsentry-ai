"""Unit and integration tests for ML Detection Ensemble and SHAP Explainability."""
import pytest
from httpx import AsyncClient
import numpy as np

from app.ml.dataset import generate_labeled_vpn_dataset
from app.ml.ensemble import MLEnsemble
from app.ml.features import (
    FEATURE_NAMES,
    extract_features_batch,
    extract_features_from_session,
)
from app.ml.isolation_forest import VPNIsolationForest
from app.ml.shap_explain import SHAPExplainer
from app.ml.xgboost_model import VPNXGBoostClassifier


# ---------------------------------------------------------------------------
# Feature Extraction Tests
# ---------------------------------------------------------------------------
def test_feature_extraction_vector_shape():
    """Verify feature vector contains exactly 12 numerical dimensions."""
    sample_session = {
        "ike_version": 2,
        "dh_group_num": 2,
        "cipher": "3DES-CBC",
        "integrity_algo": "AUTH_HMAC_MD5_96",
        "prf_algo": "PRF_HMAC_MD5",
        "exchange_types": ["IKE_SA_INIT"],
        "packet_count": 2,
        "esp_packets": 0,
        "pfs_enabled": False,
        "auth_method": "PSK",
    }
    vec = extract_features_from_session(sample_session)
    assert len(vec) == 12
    assert len(FEATURE_NAMES) == 12

    # Verify DH Group 2 maps to 80 bits
    dh_bits_idx = FEATURE_NAMES.index("dh_group_security_bits")
    assert vec[dh_bits_idx] == 80.0

    # Verify 3DES maps to score 2.0
    cipher_idx = FEATURE_NAMES.index("cipher_security_score")
    assert vec[cipher_idx] == 2.0


def test_batch_feature_extraction():
    """Verify 2D feature matrix extraction across multiple sessions."""
    sessions = [
        {"ike_version": 2, "dh_group_num": 14, "cipher": "AES-GCM-256"},
        {"ike_version": 1, "dh_group_num": 2, "cipher": "DES-CBC"},
    ]
    matrix = extract_features_batch(sessions)
    assert matrix.shape == (2, 12)


# ---------------------------------------------------------------------------
# XGBoost Model Tests
# ---------------------------------------------------------------------------
def test_xgboost_classifier_metrics():
    """Verify XGBoost achieves high precision, recall, and low false-positive rate."""
    X, y = generate_labeled_vpn_dataset()
    classifier = VPNXGBoostClassifier()
    metrics = classifier.train(X, y)

    assert metrics["accuracy"] >= 0.95
    assert metrics["precision"] >= 0.95
    assert metrics["recall"] >= 0.95
    assert metrics["false_positive_rate"] <= 0.05
    assert "confusion_matrix" in metrics


# ---------------------------------------------------------------------------
# Isolation Forest Anomaly Detector Tests
# ---------------------------------------------------------------------------
def test_isolation_forest_novel_anomaly():
    """Verify Isolation Forest flags extreme out-of-distribution traffic."""
    X, y = generate_labeled_vpn_dataset()
    X_benign = X[y == 0]

    iso = VPNIsolationForest(contamination=0.1)
    iso.train(X_benign)

    # Extreme anomalous flow: 50,000 packets, zero security bits, negative parameters
    anomalous_vector = np.array([
        1.0, 1.0, 50000.0, 0.0, 10.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0
    ], dtype=np.float32)

    anomaly_score = iso.score_anomaly(anomalous_vector)
    assert anomaly_score >= 0.50


# ---------------------------------------------------------------------------
# SHAP Explainability Tests
# ---------------------------------------------------------------------------
def test_shap_feature_attributions():
    """Verify SHAP produces ranked feature contributions for vulnerable session."""
    X, y = generate_labeled_vpn_dataset()
    classifier = VPNXGBoostClassifier()
    classifier.train(X, y)

    explainer = SHAPExplainer(classifier.model)
    # Vector representing weak DH Group 1 (64 bits) and NULL cipher (score 0.0)
    vulnerable_vec = np.array([
        2.0, 0.0, 4.0, 10.0, 64.0, 0.0, 1.0, 1.0, 0.0, 1.0, 1.0, 0.0
    ], dtype=np.float32)

    explanations = explainer.explain_session(vulnerable_vec, top_n=3)
    assert len(explanations) == 3

    top_features = [item["feature"] for item in explanations]
    assert any(f in top_features for f in ("dh_group_security_bits", "cipher_security_score"))
    for item in explanations:
        assert item["contribution_pct"] >= 0.0


# ---------------------------------------------------------------------------
# Ensemble Pipeline & API Tests
# ---------------------------------------------------------------------------
def test_ensemble_prediction_verdict():
    """Verify complete ensemble classifies secure vs vulnerable sessions correctly."""
    ensemble = MLEnsemble.get_instance()

    insecure_session = {
        "ike_version": 1,
        "exchange_types": ["Aggressive Mode"],
        "cipher": "3DES-CBC",
        "dh_group_num": 2,
        "integrity_algo": "AUTH_HMAC_MD5_96",
        "prf_algo": "PRF_HMAC_MD5",
        "packet_count": 3,
        "esp_packets": 0,
        "pfs_enabled": False,
        "auth_method": "PSK",
    }
    verdict_bad = ensemble.analyze_session(insecure_session)
    assert verdict_bad.is_vulnerable is True
    assert verdict_bad.vulnerability_probability >= 0.70
    assert len(verdict_bad.shap_explanations) > 0

    secure_session = {
        "ike_version": 2,
        "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"],
        "cipher": "AES-GCM-256",
        "dh_group_num": 19,
        "integrity_algo": "AUTH_HMAC_SHA2_256_128",
        "prf_algo": "PRF_HMAC_SHA2_256",
        "packet_count": 4,
        "esp_packets": 200,
        "pfs_enabled": True,
        "auth_method": "RSA Digital Signatures",
    }
    verdict_good = ensemble.analyze_session(secure_session)
    assert verdict_good.is_vulnerable is False
    assert verdict_good.vulnerability_probability < 0.35


@pytest.mark.asyncio
async def test_ml_metrics_api_endpoint(client: AsyncClient):
    """Test GET /api/ml/metrics endpoint returns model validation results."""
    # 1. Register & login
    await client.post("/api/auth/register", json={
        "username": "ml_analyst",
        "email": "ml@netsentry.internal",
        "password": "Password123!",
        "role": "analyst",
    })
    login_res = await client.post("/api/auth/login/json", json={
        "username": "ml_analyst",
        "password": "Password123!",
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = await client.get("/api/ml/metrics", headers=headers)
    assert response.status_code == 200
    metrics = response.json()
    assert "accuracy" in metrics
    assert "precision" in metrics
    assert "recall" in metrics
    assert "confusion_matrix" in metrics


@pytest.mark.asyncio
async def test_ml_predict_api_endpoint(client: AsyncClient):
    """Test POST /api/ml/predict endpoint for interactive session evaluation."""
    await client.post("/api/auth/register", json={
        "username": "ml_predict_user",
        "email": "ml_predict@netsentry.internal",
        "password": "Password123!",
        "role": "analyst",
    })
    login_res = await client.post("/api/auth/login/json", json={
        "username": "ml_predict_user",
        "password": "Password123!",
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "ike_version": 2,
        "dh_group_num": 2,
        "dh_group": "Group 2 (1024-bit)",
        "cipher": "3DES-CBC",
        "integrity_algo": "AUTH_HMAC_MD5_96",
        "prf_algo": "PRF_HMAC_MD5",
        "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"],
        "packet_count": 4,
        "esp_packets": 10,
        "pfs_enabled": False,
        "auth_method": "PSK",
    }
    response = await client.post("/api/ml/predict", headers=headers, json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "is_vulnerable" in data
    assert "vulnerability_probability" in data
    assert "top_shap_features" in data
    assert len(data["top_shap_features"]) > 0
