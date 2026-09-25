"""Unit and integration tests for IPsec Testbed and Traffic Profile Generator."""
import pytest
from app.testbed.generator import (
    VPNTestbedGenerator,
    IPsecTestbedGenerator,
    SUPPORTED_TESTBED_DH_GROUPS,
    SUPPORTED_TESTBED_CIPHERS,
    TestbedProfile,
)
from app.testbed.traffic_generator import (
    VPNTrafficProfileGenerator,
    SyntheticTrafficGenerator,
    TRAFFIC_PROFILES,
)


def test_testbed_supported_dh_groups():
    """Verify only supported DH groups (1, 2, 5, 14, 19, 20, 31) are marked as supported in testbed."""
    supported = set(SUPPORTED_TESTBED_DH_GROUPS.keys())
    assert supported == {1, 2, 5, 14, 19, 20, 31}
    assert 14 in supported  # Standard MODP-2048
    assert 19 in supported  # ECP-256
    assert 31 in supported  # Curve25519
    # Ensure unsupported groups like 22, 23, 24 are not claimed
    assert 22 not in supported
    assert 23 not in supported


def test_testbed_matrix_generation():
    """Verify matrix generator produces valid profiles across dimensions."""
    gen = VPNTestbedGenerator()
    matrix = gen.generate_matrix()
    assert len(matrix) > 50

    # Verify at least one profile has each expected label
    has_secure = any(p.expected_security_label == "secure" for p in matrix)
    has_vuln = any(p.expected_security_label == "vulnerable" for p in matrix)
    assert has_secure
    assert has_vuln


def test_strongswan_and_cisco_syntax():
    """Verify generated strongSwan (swanctl.conf) and Cisco IOS-XE syntax."""
    gen = VPNTestbedGenerator()
    profile = gen.create_sample_profile(
        session_id="tb-modern-001",
        ike_version=2,
        mode="tunnel",
        ip_version="IPv4",
        encryption="AES-256-GCM",
        dh_group_num=19,
        pfs_enabled=True,
    )

    swanctl_conf = gen.generate_swanctl_conf(profile)
    assert "connections {" in swanctl_conf
    assert "version = 2" in swanctl_conf
    assert "proposals = aes256gcm16-prfsha256-ecp256" in swanctl_conf
    assert "mode = tunnel" in swanctl_conf

    cisco_conf = gen.generate_cisco_ios_xe_conf(profile)
    assert "crypto ikev2 proposal" in cisco_conf
    assert "encryption aes-gcm-256" in cisco_conf
    assert "group 19" in cisco_conf
    assert "set pfs group19" in cisco_conf


def test_synthetic_traffic_generator_profiles():
    """Verify synthetic traffic generation across all 7 traffic profiles."""
    profiles = ["Web", "VoIP", "Video", "Messaging-like", "Email-like", "ICMP", "Bulk/Data"]
    for p_name in profiles:
        flow = VPNTrafficProfileGenerator.generate_flow(
            traffic_type=p_name,
            num_packets=30,
        )
        assert flow.traffic_class == p_name
        assert len(flow.packets) == 30
        assert flow.stats["packet_count"] == 30
        assert flow.stats["mean_packet_size"] > 0
        assert flow.stats["duration_seconds"] > 0


def test_synthetic_pcap_generation():
    """Verify synthetic PCAP byte generation with valid pcap header."""
    pcap_gen = SyntheticTrafficGenerator()
    pcap_bytes = pcap_gen.generate_pcap(
        scenario="IKEV2_ESTABLISHED",
        profile="Web",
        packet_count=20,
    )
    assert len(pcap_bytes) > 24
    # Standard PCAP magic header (0xa1b2c3d4 or 0xd4c3b2a1)
    magic = pcap_bytes[:4]
    assert magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1")
