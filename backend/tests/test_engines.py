"""Unit and integration tests for RuleEngine and IKEStateMachineTracker."""
import pytest
from httpx import AsyncClient

from app.engines.fsm_engine import IKEStateMachineTracker
from app.engines.rule_engine import RuleEngine
from tests.test_ingest import (
    build_synthetic_ikev2_init_packet,
    build_synthetic_pcap_bytes,
)


# ---------------------------------------------------------------------------
# RuleEngine Tests
# ---------------------------------------------------------------------------
def test_rule_engine_weak_dh_group():
    """Verify detection of insecure DH Groups 1, 2, and 5."""
    engine = RuleEngine()
    session_weak_dh = {
        "ike_version": 2,
        "dh_group_num": 2,
        "dh_group": "Group 2 (1024-bit MODP - Insecure)",
        "cipher": "AES-CBC-256",
        "integrity_algo": "AUTH_HMAC_SHA2_256_128",
        "prf_algo": "PRF_HMAC_SHA2_256",
        "pfs_enabled": True,
    }
    findings = engine.evaluate(session_weak_dh)
    rule_ids = [f["rule_id"] for f in findings]

    assert "SEC-DH-WEAK" in rule_ids
    hit = next(f for f in findings if f["rule_id"] == "SEC-DH-WEAK")
    assert hit["severity"] == "CRITICAL"
    assert "RFC 8247" in hit["rfc_reference"]


def test_rule_engine_deprecated_ciphers():
    """Verify detection of obsolete 3DES, DES, and NULL ciphers."""
    engine = RuleEngine()
    session_3des = {
        "ike_version": 2,
        "cipher": "3DES-CBC",
        "dh_group_num": 14,
        "integrity_algo": "AUTH_HMAC_SHA2_256_128",
        "prf_algo": "PRF_HMAC_SHA2_256",
        "pfs_enabled": True,
    }
    findings = engine.evaluate(session_3des)
    rule_ids = [f["rule_id"] for f in findings]

    assert "SEC-CIPHER-DEPRECATED" in rule_ids
    hit = next(f for f in findings if f["rule_id"] == "SEC-CIPHER-DEPRECATED")
    assert hit["severity"] == "CRITICAL"
    assert "RFC 8221" in hit["rfc_reference"]


def test_rule_engine_weak_integrity_md5():
    """Verify detection of deprecated MD5/SHA1 integrity and PRF."""
    engine = RuleEngine()
    session_md5 = {
        "ike_version": 2,
        "cipher": "AES-CBC-128",
        "dh_group_num": 14,
        "integrity_algo": "AUTH_HMAC_MD5_96",
        "prf_algo": "PRF_HMAC_MD5",
        "pfs_enabled": True,
    }
    findings = engine.evaluate(session_md5)
    rule_ids = [f["rule_id"] for f in findings]

    assert "SEC-INTEG-WEAK" in rule_ids
    hit = next(f for f in findings if f["rule_id"] == "SEC-INTEG-WEAK")
    assert hit["severity"] == "HIGH"


def test_rule_engine_ikev1_aggressive_mode():
    """Verify detection of cleartext PSK exposure in IKEv1 Aggressive Mode."""
    engine = RuleEngine()
    session_am = {
        "ike_version": 1,
        "exchange_type": "Aggressive Mode",
        "exchange_types": ["Aggressive Mode"],
        "cipher": "AES-CBC-128",
        "dh_group_num": 14,
        "auth_method": "Pre-Shared Key (PSK)",
        "pfs_enabled": False,
    }
    findings = engine.evaluate(session_am)
    rule_ids = [f["rule_id"] for f in findings]

    assert "SEC-IKEV1-AGGRESSIVE" in rule_ids
    hit = next(f for f in findings if f["rule_id"] == "SEC-IKEV1-AGGRESSIVE")
    assert hit["severity"] == "CRITICAL"
    assert "RFC 2409" in hit["rfc_reference"]


def test_clean_modern_ikev2_session():
    """Verify modern hardened IKEv2 session triggers 0 CRITICAL or HIGH findings."""
    engine = RuleEngine()
    secure_session = {
        "ike_version": 2,
        "cipher": "AES-GCM-256",
        "dh_group_num": 19,
        "dh_group": "Group 19 (256-bit Random ECP)",
        "integrity_algo": "AUTH_HMAC_SHA2_256_128",
        "prf_algo": "PRF_HMAC_SHA2_256",
        "pfs_enabled": True,
        "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"],
    }
    findings = engine.evaluate(secure_session)
    critical_or_high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]

    assert len(critical_or_high) == 0


# ---------------------------------------------------------------------------
# IKEStateMachineTracker Tests
# ---------------------------------------------------------------------------
def test_fsm_completed_ikev2_handshake():
    """Verify completed IKEv2 handshake (INIT -> AUTH) yields clean state."""
    tracker = IKEStateMachineTracker()
    session = {
        "ike_version": 2,
        "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"],
        "packet_count": 4,
        "esp_packets": 10,
    }
    findings = tracker.evaluate_session(session)
    assert len(findings) == 0


def test_fsm_truncated_ikev2_handshake():
    """Verify detection of premature termination after IKE_SA_INIT."""
    tracker = IKEStateMachineTracker()
    session_truncated = {
        "ike_version": 2,
        "exchange_types": ["IKE_SA_INIT"],
        "packet_count": 2,
        "esp_packets": 0,
    }
    findings = tracker.evaluate_session(session_truncated)
    rule_ids = [f["rule_id"] for f in findings]

    assert "FSM-IKEV2-PREMATURE-TERMINATION" in rule_ids
    hit = next(f for f in findings if f["rule_id"] == "FSM-IKEV2-PREMATURE-TERMINATION")
    assert hit["severity"] == "HIGH"


def test_fsm_truncated_ikev1_main_mode():
    """Verify detection of incomplete 6-packet IKEv1 Main Mode."""
    tracker = IKEStateMachineTracker()
    session_incomplete = {
        "ike_version": 1,
        "exchange_types": ["Identity Protection (Main Mode)"],
        "packet_count": 3,
        "esp_packets": 0,
    }
    findings = tracker.evaluate_session(session_incomplete)
    rule_ids = [f["rule_id"] for f in findings]

    assert "FSM-IKEV1-TRUNCATED-MAIN-MODE" in rule_ids


def test_fsm_protocol_downgrade_signal():
    """Verify detection of concurrent IKEv1 and IKEv2 signaling indicating downgrade."""
    tracker = IKEStateMachineTracker()
    session_downgrade = {
        "ike_version": 2,
        "exchange_types": ["IKE_SA_INIT", "Identity Protection (Main Mode)"],
        "packet_count": 5,
        "esp_packets": 0,
    }
    findings = tracker.evaluate_session(session_downgrade)
    rule_ids = [f["rule_id"] for f in findings]

    assert "FSM-DOWNGRADE-SIGNAL" in rule_ids
    hit = next(f for f in findings if f["rule_id"] == "FSM-DOWNGRADE-SIGNAL")
    assert hit["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# End-to-End Pipeline & Findings Persistence Test
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_end_to_end_worker_persists_findings(client: AsyncClient):
    """Verify uploaded capture triggers rule engine and persists findings in DB."""
    # 1. Register & Login
    await client.post("/api/auth/register", json={
        "username": "engine_tester",
        "email": "engine_tester@netsentry.internal",
        "password": "Password123!",
        "role": "analyst",
    })
    login_res = await client.post("/api/auth/login/json", json={
        "username": "engine_tester",
        "password": "Password123!",
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Build synthetic packet with weak DH Group 2 (1024-bit) and single DES
    raw_packet = build_synthetic_ikev2_init_packet(
        dh_group_id=2,   # Insecure Group 2
        encr_id=2,       # Insecure Single DES
        key_len=56,
    )
    pcap_bytes = build_synthetic_pcap_bytes(raw_packet)

    # 3. Upload file
    files = {"file": ("weak_crypto.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")}
    upload_res = await client.post("/api/ingest/upload", headers=headers, files=files)
    assert upload_res.status_code == 202
    job_id = upload_res.json()["id"]

    # 4. Fetch findings from API
    findings_res = await client.get(f"/api/ingest/jobs/{job_id}/findings", headers=headers)
    assert findings_res.status_code == 200
    findings_list = findings_res.json()

    # Must catch weak DH Group 2 and DES cipher!
    rule_ids = [f["rule_id"] for f in findings_list]
    assert "SEC-DH-WEAK" in rule_ids
    assert "SEC-CIPHER-DEPRECATED" in rule_ids
    # Also truncated handshake since only INIT was present without AUTH
    assert "FSM-IKEV2-PREMATURE-TERMINATION" in rule_ids
