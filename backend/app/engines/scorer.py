"""Risk Scoring Engine: Calculates explainable 0-100 risk score based on findings and ML telemetry."""
from dataclasses import dataclass
import json
from typing import Any, Dict, List, Optional


@dataclass
class RiskScoreResult:
    overall_score: float  # 0.0 - 100.0 (Higher = Higher Risk)
    risk_level: str       # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SECURE'
    findings_summary: Dict[str, int]
    executive_summary: str


class RiskScorer:
    """Computes weighted, explainable 0-100 risk score and security level classification."""

    SEVERITY_WEIGHTS = {
        "CRITICAL": 35.0,
        "HIGH": 20.0,
        "MEDIUM": 10.0,
        "LOW": 5.0,
        "INFO": 0.0,
    }

    @classmethod
    def calculate_score(
        cls,
        findings: List[Dict[str, Any]],
        ml_vulnerability_prob: Optional[float] = None,
        ml_anomaly_score: Optional[float] = None,
    ) -> RiskScoreResult:
        """
        Calculate composite risk score:
        - Weighted severity penalties for RFC violations and state anomalies
        - Additional weighting for ML vulnerability confidence
        """
        summary_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        # Deduplicate findings by rule_id for scoring so identical rules across packets don't over-penalize
        seen_rules = set()
        penalty = 0.0

        for f in findings:
            sev = str(f.get("severity", "MEDIUM")).upper()
            rid = f.get("rule_id", "UNKNOWN")

            if sev in summary_counts:
                summary_counts[sev] += 1

            if rid not in seen_rules:
                seen_rules.add(rid)
                penalty += cls.SEVERITY_WEIGHTS.get(sev, 10.0)

        # ML influence: add up to 25 points if ML predicts high vulnerability confidence
        if ml_vulnerability_prob is not None:
            penalty += ml_vulnerability_prob * 25.0

        # Anomaly influence: add up to 10 points if anomaly detector flags unusual deviation
        if ml_anomaly_score is not None and ml_anomaly_score >= 0.65:
            penalty += (ml_anomaly_score - 0.65) * 20.0

        # Scale and clamp between 0.0 and 100.0
        final_score = round(min(100.0, max(0.0, penalty)), 1)

        # Determine risk classification level
        if final_score >= 75.0:
            risk_level = "CRITICAL"
        elif final_score >= 50.0:
            risk_level = "HIGH"
        elif final_score >= 25.0:
            risk_level = "MEDIUM"
        elif final_score >= 8.0:
            risk_level = "LOW"
        else:
            risk_level = "SECURE"

        # Executive summary generation
        crit = summary_counts["CRITICAL"]
        high = summary_counts["HIGH"]
        med = summary_counts["MEDIUM"]

        if crit > 0:
            exec_summary = (
                f"CRITICAL RISK (Score {final_score}/100): The session exhibits severe cryptographic "
                f"weaknesses ({crit} critical, {high} high findings). Immediate remediation is required to prevent "
                f"potential session decryption, credential compromise, or MITM interception."
            )
        elif high > 0:
            exec_summary = (
                f"HIGH RISK (Score {final_score}/100): The VPN configuration contains deprecated algorithms or "
                f"state sequencing anomalies ({high} high findings). Upgrades to RFC 8247-compliant suites are recommended."
            )
        elif med > 0:
            exec_summary = (
                f"MODERATE RISK (Score {final_score}/100): Minor non-conformances identified (e.g. missing PFS or "
                f"legacy protocol use). Security posture should be hardened."
            )
        else:
            exec_summary = (
                f"HEALTHY & SECURE (Score {final_score}/100): No critical RFC non-conformances detected. "
                f"Modern cryptographic suites and valid protocol state sequences verified."
            )

        return RiskScoreResult(
            overall_score=final_score,
            risk_level=risk_level,
            findings_summary=summary_counts,
            executive_summary=exec_summary,
        )
