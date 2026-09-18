"""Tests for RiskScorer, RemediationGenerator, PDFReportGenerator, and Assessment Router."""
import io
import json
import pytest
from httpx import AsyncClient
from scapy.layers.inet import IP, UDP
from scapy.utils import PcapWriter

from app.engines.scorer import RiskScorer
from app.engines.remediation import RemediationGenerator
from app.reports.pdf_generator import PDFReportGenerator
from app.parsers.ike_parser import ParsedVPNSessionData
from tests.test_ingest import build_synthetic_ikev2_init_packet, build_synthetic_pcap_bytes


# ---------------------------------------------------------------------------
# Unit Tests: Risk Scorer
# ---------------------------------------------------------------------------
def test_risk_scorer_empty_findings():
    """Zero findings should produce score 0.0 and 'SECURE' risk level."""
    result = RiskScorer.calculate_score([], ml_vulnerability_prob=0.0, ml_anomaly_score=0.0)
    assert result.overall_score == 0.0
    assert result.risk_level == "SECURE"
    assert result.findings_summary["CRITICAL"] == 0
    assert "secure" in result.executive_summary.lower()


def test_risk_scorer_critical_findings():
    """Multiple high/critical findings scale score to CRITICAL (>75)."""
    findings = [
        {"rule_id": "IKE-CRYPTO-WEAK-DH-1", "severity": "CRITICAL", "title": "Weak DH 1"},
        {"rule_id": "IKE-CRYPTO-DEPRECATED-CIPHER-3DES", "severity": "HIGH", "title": "3DES"},
        {"rule_id": "IKE-CRYPTO-DEPRECATED-INTEG-MD5", "severity": "HIGH", "title": "MD5"},
    ]
    result = RiskScorer.calculate_score(findings, ml_vulnerability_prob=0.95, ml_anomaly_score=0.85)
    assert result.overall_score >= 75.0
    assert result.risk_level == "CRITICAL"
    assert result.findings_summary["CRITICAL"] == 1
    assert result.findings_summary["HIGH"] == 2
    assert "CRITICAL RISK" in result.executive_summary


def test_risk_scorer_medium_and_low():
    """Medium and low findings produce MEDIUM risk level."""
    findings = [
        {"rule_id": "IKE-CRYPTO-NO-PFS", "severity": "MEDIUM", "title": "No PFS"},
        {"rule_id": "IKE-STATE-NO-AUTH", "severity": "LOW", "title": "Informational"},
    ]
    result = RiskScorer.calculate_score(findings, ml_vulnerability_prob=0.2, ml_anomaly_score=0.1)
    assert 10.0 <= result.overall_score < 50.0
    assert result.risk_level in ("MEDIUM", "LOW")


# ---------------------------------------------------------------------------
# Unit Tests: Remediation Generator
# ---------------------------------------------------------------------------
def test_remediation_generator_swanctl():
    """Verify strongSwan remediated config contains hardened RFC 8247 proposals."""
    session_data = ParsedVPNSessionData(
        session_key="test_session",
        ike_version=1,
        src_ip="192.168.1.100",
        dst_ip="198.51.100.1",
        src_port=500,
        dst_port=500,
        initiator_spi="1122334455667788",
        responder_spi="8877665544332211",
        cipher="3DES-CBC",
        dh_group="Group 2 (1024-bit MODP - Insecure)",
        dh_group_num=2,
        integrity_algo="AUTH_HMAC_MD5_128",
        pfs_enabled=False,
    )
    diff = RemediationGenerator.generate_swanctl_diff(session_data, [])
    assert "aes256gcm16" in diff["after"]
    assert "modp2048" in diff["after"]
    assert "3des" in diff["before"]


def test_remediation_generator_cisco():
    """Verify Cisco IOS remediated config contains modern IKEv2 and AES-GCM-256."""
    session_data = ParsedVPNSessionData(
        session_key="test_session_cisco",
        ike_version=1,
        src_ip="192.168.1.100",
        dst_ip="198.51.100.1",
        src_port=500,
        dst_port=500,
        initiator_spi="1122334455667788",
        responder_spi="8877665544332211",
        cipher="3DES-CBC",
        dh_group_num=2,
    )
    diff = RemediationGenerator.generate_cisco_diff(session_data, [])
    assert "crypto ikev2 proposal" in diff["after"]
    assert "encryption aes-gcm-256" in diff["after"]
    assert "crypto isakmp policy" in diff["before"]


# ---------------------------------------------------------------------------
# Unit Tests: PDF Report Generator
# ---------------------------------------------------------------------------
def test_pdf_report_generator():
    """Ensure PDF report produces valid PDF document bytes."""
    job_info = {"id": "test-job-uuid-1234", "filename": "sample_traffic.pcap"}
    assessment_data = {
        "overall_score": 85.0,
        "risk_level": "CRITICAL",
        "executive_summary": "Critical cryptographic flaws detected.",
        "config_diff_before": "# Before config",
        "config_diff_after": "# After config",
    }
    findings = [
        {
            "rule_id": "IKE-CRYPTO-WEAK-DH-2",
            "severity": "HIGH",
            "title": "Weak Diffie-Hellman Group 2",
            "description": "DH Group 2 (1024-bit) is susceptible to discrete log factorization.",
            "rfc_reference": "RFC 8247 Section 2.4",
            "remediation_hint": "Upgrade to Group 14 or Group 19.",
        }
    ]
    ml_metrics = {"accuracy": 1.0, "precision": 1.0, "recall": 1.0, "false_positive_rate": 0.0}

    pdf_bytes = PDFReportGenerator.generate(job_info, assessment_data, findings, ml_metrics)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes[:4] == b"%PDF"


# ---------------------------------------------------------------------------
# Integration Tests: Assessment Endpoints
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_assessment_flow_end_to_end(client: AsyncClient):
    """End-to-end test: upload PCAP -> background worker runs -> query assessment & download PDF."""
    # 1. Register & login
    await client.post("/api/auth/register", json={
        "username": "auditor_user",
        "email": "auditor@netsentry.internal",
        "password": "Password123!",
        "role": "analyst",
    })
    login_res = await client.post("/api/auth/login/json", json={
        "username": "auditor_user",
        "password": "Password123!",
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Build synthetic PCAP with insecure DH Group 2 and 3DES
    packet = build_synthetic_ikev2_init_packet(dh_group_id=2, encr_id=3)  # DH 2, 3DES
    pcap_content = build_synthetic_pcap_bytes(packet)

    # 3. Upload file
    files = {"file": ("insecure_vpn.pcap", pcap_content, "application/vnd.tcpdump.pcap")}
    upload_res = await client.post("/api/ingest/upload", headers=headers, files=files)
    assert upload_res.status_code == 202
    job_id = upload_res.json()["id"]

    # 4. Fetch assessment
    assess_res = await client.get(f"/api/assessments/{job_id}", headers=headers)
    assert assess_res.status_code == 200
    assessment = assess_res.json()
    assert assessment["upload_id"] == job_id
    assert assessment["overall_score"] > 0.0
    assert assessment["risk_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SECURE")
    assert "swanctl" in assessment["config_diff_before"].lower() or "cisco" in assessment["config_diff_before"].lower()

    # 5. Download PDF
    pdf_res = await client.get(f"/api/assessments/{job_id}/pdf", headers=headers)
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content[:4] == b"%PDF"


@pytest.mark.asyncio
async def test_assessment_unauthorized(client: AsyncClient):
    """Assessment and PDF download require authentication."""
    res1 = await client.get("/api/assessments/any-job-id")
    assert res1.status_code == 401

    res2 = await client.get("/api/assessments/any-job-id/pdf")
    assert res2.status_code == 401
