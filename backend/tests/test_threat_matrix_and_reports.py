"""Unit tests for Threat Matrix, Protocol Identification taxonomy, Metadata Exposure, and Dual PDF Reports."""
import pytest

from app.engines.threat_matrix import ThreatMatrixEngine, ThreatMatrixResult
from app.engines.protocol_ident import ProtocolIdentifier
from app.engines.metadata_exposure import MetadataExposureAnalyzer
from app.reports.pdf_generator import PDFReportGenerator


def test_threat_matrix_7_columns_and_observability():
    """Verify Threat Matrix consolidates rule findings and assigns 7 columns and observability."""
    engine = ThreatMatrixEngine()
    rule_findings = [
        {
            "id": "FIND-01",
            "rule_id": "SEC-DH-WEAK",
            "title": "Insecure Diffie-Hellman Group 2",
            "severity": "CRITICAL",
            "evidence": "Negotiated transform ID = 2 (MODP-1024)",
            "reference": "RFC 8247 Section 2.4",
            "recommendation": "Upgrade to Group 14 or Group 19",
        }
    ]
    fsm_results = [
        {
            "session_id": "session-12345",
            "anomalies": ["Handshake truncated after IKE_SA_INIT"],
            "final_state": "SA_INIT_COMPLETED",
            "handshake_completed": False,
        }
    ]

    res = engine.generate_matrix(rule_findings=rule_findings, fsm_results=fsm_results)
    assert isinstance(res, ThreatMatrixResult)
    assert len(res.entries) >= 2

    # Check 7 standard columns on first entry
    entry = res.entries[0]
    assert hasattr(entry, "finding")
    assert hasattr(entry, "severity")
    assert hasattr(entry, "evidence")
    assert hasattr(entry, "impact")
    assert hasattr(entry, "confidence")
    assert hasattr(entry, "reference")
    assert hasattr(entry, "recommendation")

    # Observability status
    assert entry.observability in ("OBSERVED", "INFERRED", "NOT_OBSERVABLE")
    assert res.summary.critical_count >= 1


def test_protocol_ident_observability_taxonomy():
    """Verify Protocol Identification strictly labels Child SA encryption as NOT_OBSERVABLE without keys."""
    ident = ProtocolIdentifier()
    session = {
        "id": 1,
        "ike_version": 2,
        "exchange_type": "IKE_SA_INIT",
        "cipher": "AES-CBC-128",
        "dh_group_num": 14,
        "esp_packets": 20,
        "pfs_enabled": False,
    }
    result = ident.analyze_session(session)
    assert result.session_id == "1"

    statuses = {c.property: c.observability for c in result.characteristics}
    # Child SA Encryption must be NOT_OBSERVABLE from passive PCAP alone
    if "Child SA Encryption" in statuses:
        assert statuses["Child SA Encryption"] == "NOT_OBSERVABLE"

    # IKE Version is OBSERVED
    assert statuses.get("IKE Version") == "OBSERVED"


def test_metadata_exposure_scoring():
    """Verify Metadata Exposure calculates leakage score and side-channel inferences."""
    analyzer = MetadataExposureAnalyzer()
    session = {
        "src_ip": "192.168.1.100",
        "dst_ip": "198.51.100.1",
        "src_port": 4500,
        "dst_port": 4500,
        "ike_version": 2,
        "exchange_type": "IKE_AUTH",
        "esp_packets": 50,
        "initiator_spi": "1122334455667788",
    }
    res = analyzer.analyze(session)
    assert res.exposure_score > 0.0
    assert res.exposure_level in ("HIGH", "MEDIUM", "LOW")
    assert len(res.observable_elements) >= 3
    assert len(res.confidential_elements) >= 2


def test_dual_pdf_generation_executive_and_technical():
    """Verify both Executive PDF and Technical Audit PDF generate valid PDF bytes."""
    job_info = {"id": "test-job-99", "filename": "sample_traffic.pcap"}
    assessment_data = {
        "overall_score": 75.0,
        "risk_level": "HIGH",
        "executive_summary": "High cryptographic risk identified.",
        "config_diff_before": "cipher 3des",
        "config_diff_after": "cipher aes-gcm-256",
    }
    threat_matrix = {
        "entries": [
            {
                "finding": "Weak DH Group 2",
                "severity": "CRITICAL",
                "evidence": "ID=2",
                "impact": "Logjam vulnerability",
                "confidence": "HIGH",
                "reference": "RFC 8247",
                "recommendation": "Upgrade to Group 14",
                "observability": "OBSERVED",
            }
        ],
        "summary": {
            "observed_count": 1,
            "inferred_count": 0,
            "not_observable_count": 1,
        }
    }

    # 1. Executive PDF
    exec_pdf = PDFReportGenerator.generate_executive_pdf(
        job_info=job_info,
        assessment_data=assessment_data,
        threat_matrix=threat_matrix,
    )
    assert exec_pdf.startswith(b"%PDF")
    assert len(exec_pdf) > 1000

    # 2. Technical PDF
    tech_pdf = PDFReportGenerator.generate_technical_pdf(
        job_info=job_info,
        assessment_data=assessment_data,
        threat_matrix=threat_matrix,
    )
    assert tech_pdf.startswith(b"%PDF")
    assert len(tech_pdf) > 1000
