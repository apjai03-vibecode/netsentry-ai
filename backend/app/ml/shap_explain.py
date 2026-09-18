"""SHAP Explainability Layer for XGBoost VPN security predictions."""
import logging
from typing import Any, Dict, List, Optional
import numpy as np
import xgboost as xgb

from app.ml.features import FEATURE_NAMES

logger = logging.getLogger(__name__)

# Attempt to import shap optionally without failing if host AppLocker restricts scipy DLLs
try:
    import shap
    _HAS_SHAP = True
except Exception:
    _HAS_SHAP = False

FEATURE_DESCRIPTIONS = {
    "ike_version": "Protocol version selection (IKEv1 vs IKEv2)",
    "is_aggressive_mode": "IKEv1 Aggressive Mode cleartext credential exposure",
    "packet_count": "Abnormal handshake packet exchange volume",
    "esp_packet_count": "Encapsulating Security Payload (ESP) volume",
    "dh_group_security_bits": "Diffie-Hellman key exchange cryptographic strength",
    "cipher_security_score": "Symmetric encryption cipher security classification",
    "integrity_security_score": "Integrity and authentication algorithm security",
    "prf_security_score": "Pseudorandom function (PRF) cryptographic strength",
    "has_pfs": "Perfect Forward Secrecy (PFS) session isolation",
    "auth_method_score": "Authentication mechanism (PSK vs Digital Signature)",
    "handshake_complete": "Handshake completion status",
    "downgrade_signal": "Protocol version downgrade or fallback indicator",
}


class SHAPExplainer:
    """Computes TreeExplainer SHAP values and human-readable feature attribution percentages."""

    def __init__(self, xgb_model: Any):
        self.xgb_model = xgb_model
        self.explainer = None
        self.is_ready = False

        if _HAS_SHAP:
            try:
                self.explainer = shap.TreeExplainer(xgb_model)
                self.is_ready = True
                logger.info("SHAP TreeExplainer initialized successfully.")
            except Exception as e:
                logger.info(f"Using native XGBoost Tree SHAP predictor: {e}")
        else:
            logger.info("Using native XGBoost C++ Tree SHAP predictor.")

    def explain_session(self, X: np.ndarray, top_n: int = 4) -> List[Dict[str, Any]]:
        """
        Calculates feature attributions for a single session vector.
        Uses native XGBoost Tree SHAP calculation (pred_contribs=True) or SHAP TreeExplainer.
        Returns top_n contributors with percentage contribution and human-readable context.
        """
        if X.ndim == 1:
            X = X.reshape(1, -1)

        feature_values = X[0]
        attributions: List[Dict[str, Any]] = []

        # 1. Primary: Native XGBoost Tree SHAP calculation (built-in C++ Tree SHAP)
        try:
            booster = getattr(self.xgb_model, "get_booster", None)
            if booster:
                dmat = xgb.DMatrix(X, feature_names=FEATURE_NAMES)
                contribs = booster().predict(dmat, pred_contribs=True)[0]
                # First 12 values are feature SHAP values, last value is bias
                shap_vals = contribs[:-1]

                abs_vals = np.abs(shap_vals)
                total_impact = float(np.sum(abs_vals))

                for i, fname in enumerate(FEATURE_NAMES):
                    val = float(feature_values[i])
                    impact = float(shap_vals[i])
                    pct = round((abs(impact) / total_impact * 100.0), 1) if total_impact > 0 else 0.0

                    attributions.append({
                        "feature": fname,
                        "feature_name": FEATURE_DESCRIPTIONS.get(fname, fname),
                        "feature_value": val,
                        "shap_value": round(impact, 4),
                        "contribution_pct": pct,
                        "direction": "Risk Driver" if impact > 0 else "Protective Factor",
                    })

                attributions.sort(key=lambda x: x["contribution_pct"], reverse=True)
                return attributions[:top_n]
        except Exception as e:
            logger.warning(f"Native Tree SHAP failed ({e}), attempting fallback.")

        # 2. Secondary: SHAP library TreeExplainer if available
        if self.is_ready and self.explainer is not None:
            try:
                shap_values = self.explainer.shap_values(X)
                vals = shap_values[1][0] if isinstance(shap_values, list) else shap_values[0]
                abs_vals = np.abs(vals)
                total_impact = float(np.sum(abs_vals))

                for i, fname in enumerate(FEATURE_NAMES):
                    val = float(feature_values[i])
                    impact = float(vals[i])
                    pct = round((abs(impact) / total_impact * 100.0), 1) if total_impact > 0 else 0.0

                    attributions.append({
                        "feature": fname,
                        "feature_name": FEATURE_DESCRIPTIONS.get(fname, fname),
                        "feature_value": val,
                        "shap_value": round(impact, 4),
                        "contribution_pct": pct,
                        "direction": "Risk Driver" if impact > 0 else "Protective Factor",
                    })

                attributions.sort(key=lambda x: x["contribution_pct"], reverse=True)
                return attributions[:top_n]
            except Exception:
                pass

        return []
