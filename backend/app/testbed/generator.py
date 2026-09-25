"""VPN Testbed & Dataset Generator Module.
Generates strongSwan and Cisco IOS-XE configurations across the complete testbed matrix.
"""
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
import json


@dataclass
class TestbedProfile:
    __test__ = False
    session_id: str
    ike_version: int                # 1 or 2
    exchange_mode: str              # 'main', 'aggressive', 'ikev2'
    mode: str                       # 'tunnel' or 'transport'
    ip_version: str                 # 'IPv4' or 'IPv6'
    encryption: str                 # 'AES-128-GCM', 'AES-256-GCM', 'AES-128-CBC', 'AES-256-CBC', '3DES-CBC', 'DES-CBC'
    integrity: str                  # 'HMAC-SHA2-256', 'HMAC-SHA2-384', 'HMAC-SHA2-512', 'HMAC-SHA1', 'HMAC-MD5', 'AEAD'
    dh_group_num: int               # 1, 2, 5, 14, 19, 20, 31 (supported in testbed)
    dh_group_name: str
    pfs_enabled: bool
    traffic_type: str               # 'Web', 'VoIP', 'Video', 'Messaging-like', 'Email-like', 'ICMP', 'Bulk/Data'
    expected_security_label: str    # 'secure' or 'vulnerable'
    vulnerability_reason: Optional[str] = None

    def model_dump(self) -> Dict[str, Any]:
        return asdict(self)

    def dict(self) -> Dict[str, Any]:
        return asdict(self)
        return asdict(self)


# Testbed supported Diffie-Hellman groups (actually supported in open-source strongSwan)
TESTBED_DH_GROUPS = {
    1: {"name": "Group 1 (768-bit MODP)", "slug": "modp768", "bits": 64, "status": "deprecated"},
    2: {"name": "Group 2 (1024-bit MODP)", "slug": "modp1024", "bits": 80, "status": "deprecated"},
    5: {"name": "Group 5 (1536-bit MODP)", "slug": "modp1536", "bits": 96, "status": "deprecated"},
    14: {"name": "Group 14 (2048-bit MODP)", "slug": "modp2048", "bits": 112, "status": "standard"},
    19: {"name": "Group 19 (256-bit ECP / NIST P-256)", "slug": "ecp256", "bits": 128, "status": "recommended"},
    20: {"name": "Group 20 (384-bit ECP / NIST P-384)", "slug": "ecp384", "bits": 192, "status": "recommended"},
    31: {"name": "Group 31 (Curve25519 / RFC 8031)", "slug": "curve25519", "bits": 128, "status": "recommended"},
}

CIPHER_MAP_SWAN = {
    "AES-128-GCM": "aes128gcm16",
    "AES-256-GCM": "aes256gcm16",
    "AES-128-CBC": "aes128",
    "AES-256-CBC": "aes256",
    "3DES-CBC": "3des",
    "DES-CBC": "des",
}

INTEG_MAP_SWAN = {
    "HMAC-SHA2-256": "sha256",
    "HMAC-SHA2-384": "sha384",
    "HMAC-SHA2-512": "sha512",
    "HMAC-SHA1": "sha1",
    "HMAC-MD5": "md5",
    "AEAD": "",
}


class VPNTestbedGenerator:
    """Generates strongSwan and Cisco IOS-XE configuration templates across testbed matrix."""

    @classmethod
    def get_supported_matrix(cls) -> Dict[str, Any]:
        """Return catalog of supported testbed dimensions."""
        return {
            "ike_versions": [1, 2],
            "exchange_modes": ["Main Mode (IKEv1)", "Aggressive Mode (IKEv1)", "IKE_SA_INIT (IKEv2)"],
            "modes": ["tunnel", "transport"],
            "ip_versions": ["IPv4", "IPv6"],
            "ciphers": list(CIPHER_MAP_SWAN.keys()),
            "integrity_algorithms": list(INTEG_MAP_SWAN.keys()),
            "dh_groups": {k: v["name"] for k, v in TESTBED_DH_GROUPS.items()},
            "pfs_options": [True, False],
            "traffic_types": ["Web", "VoIP", "Video", "Messaging-like", "Email-like", "ICMP", "Bulk/Data"],
        }

    @classmethod
    def generate_swanctl_conf(cls, profile: TestbedProfile) -> str:
        """Generate strongSwan swanctl.conf configuration syntax."""
        c_swan = CIPHER_MAP_SWAN.get(profile.encryption, "aes256gcm16")
        h_swan = INTEG_MAP_SWAN.get(profile.integrity, "")
        dh_info = TESTBED_DH_GROUPS.get(profile.dh_group_num, TESTBED_DH_GROUPS[14])
        dh_slug = dh_info["slug"]

        # Build proposal string
        if "gcm" in c_swan.lower():
            ike_proposal = f"{c_swan}-prfsha256-{dh_slug}"
            esp_proposal = f"{c_swan}{f'-{dh_slug}' if profile.pfs_enabled else ''}"
        else:
            ike_proposal = f"{c_swan}-{h_swan or 'sha256'}-{dh_slug}"
            esp_proposal = f"{c_swan}-{h_swan or 'sha256'}{f'-{dh_slug}' if profile.pfs_enabled else ''}"

        local_ip = "2001:db8::1" if profile.ip_version == "IPv6" else "192.168.1.100"
        remote_ip = "2001:db8::2" if profile.ip_version == "IPv6" else "198.51.100.1"
        local_ts = "2001:db8:1::/64" if profile.ip_version == "IPv6" else "10.1.0.0/24"
        remote_ts = "2001:db8:2::/64" if profile.ip_version == "IPv6" else "10.2.0.0/24"

        is_aggr = "yes" if profile.ike_version == 1 and profile.exchange_mode == "aggressive" else "no"

        conf = f"""# strongSwan swanctl.conf - NetSentry Testbed Configuration
# Session ID: {profile.session_id} | Security Label: {profile.expected_security_label.upper()}
connections {{
    netsentry-testbed {{
        version = {profile.ike_version}
        proposals = {ike_proposal}
        aggressive = {is_aggr}
        local_addrs = {local_ip}
        remote_addrs = {remote_ip}

        local {{
            auth = psk
            id = vpn-client@netsentry.internal
        }}
        remote {{
            auth = psk
        }}

        children {{
            traffic-flow {{
                esp_proposals = {esp_proposal}
                mode = {profile.mode}
                local_ts = {local_ts}
                remote_ts = {remote_ts}
                dpd_action = restart
            }}
        }}
    }}
}}

secrets {{
    ike-netsentry {{
        secret = "NetSentryTestbedPSKSecret2026!"
    }}
}}"""
        return conf

    @classmethod
    def generate_cisco_ios_xe_conf(cls, profile: TestbedProfile) -> str:
        """Generate Cisco IOS-XE template configuration."""
        dh_group = profile.dh_group_num
        is_gcm = "gcm" in profile.encryption.lower()
        enc_cisco = "aes-gcm-256" if "256-gcm" in profile.encryption.lower() else (
            "aes-gcm-128" if "128-gcm" in profile.encryption.lower() else (
                "aes 256" if "256" in profile.encryption else (
                    "3des" if "3DES" in profile.encryption else "des"
                )
            )
        )
        hash_cisco = "sha256" if "256" in profile.integrity else (
            "sha384" if "384" in profile.integrity else (
                "md5" if "MD5" in profile.integrity else "sha"
            )
        )

        pfs_line = f" set pfs group{dh_group}" if profile.pfs_enabled else " ! PFS is disabled"

        if profile.ike_version == 2:
            return f"""! Cisco IOS-XE Configuration Template - NetSentry Testbed
! Session ID: {profile.session_id} | Mode: {profile.mode.upper()} | IP: {profile.ip_version}
crypto ikev2 proposal NETSENTRY_PROP_{profile.session_id[:6]}
 encryption {enc_cisco}
 prf {hash_cisco}
 group {dh_group}
!
crypto ikev2 policy NETSENTRY_POL_{profile.session_id[:6]}
 proposal NETSENTRY_PROP_{profile.session_id[:6]}
!
crypto ipsec transform-set TS_{profile.session_id[:6]} {'esp-gcm 256' if is_gcm else f'esp-aes {hash_cisco}-hmac'}
 mode {profile.mode}
!
crypto ipsec profile NETSENTRY_PROFILE_{profile.session_id[:6]}
 set transform-set TS_{profile.session_id[:6]}
{pfs_line}
 set ikev2-policy NETSENTRY_POL_{profile.session_id[:6]}
!
interface Tunnel100
 ip address 10.255.255.1 255.255.255.252
 tunnel source GigabitEthernet0/0
 tunnel destination 198.51.100.1
 tunnel mode ipsec {'ipv6' if profile.ip_version == 'IPv6' else 'ipv4'}
 tunnel protection ipsec profile NETSENTRY_PROFILE_{profile.session_id[:6]}"""
        else:
            return f"""! Cisco IOS-XE IKEv1 Legacy Configuration Template - NetSentry Testbed
! Session ID: {profile.session_id} | Exchange: {profile.exchange_mode.upper()}
crypto isakmp policy 10
 encr {enc_cisco}
 hash {hash_cisco}
 authentication pre-share
 group {dh_group}
 lifetime 86400
!
crypto ipsec transform-set LEGACY_TS_{profile.session_id[:6]} esp-3des esp-md5-hmac
 mode {profile.mode}
!
crypto map NETSENTRY_MAP 10 ipsec-isakmp
 set peer 198.51.100.1
 set transform-set LEGACY_TS_{profile.session_id[:6]}
{pfs_line}
 match address 101"""

    @classmethod
    def create_sample_profile(
        cls,
        session_id: str = "tb-sample-001",
        ike_version: int = 2,
        exchange_mode: str = "ikev2",
        mode: str = "tunnel",
        ip_version: str = "IPv4",
        encryption: str = "AES-256-GCM",
        integrity: str = "AEAD",
        dh_group_num: int = 19,
        pfs_enabled: bool = True,
        traffic_type: str = "Web",
    ) -> TestbedProfile:
        """Create a validated TestbedProfile instance."""
        dh_info = TESTBED_DH_GROUPS.get(dh_group_num, TESTBED_DH_GROUPS[14])
        is_vuln = (
            dh_group_num in (1, 2, 5) or
            encryption in ("3DES-CBC", "DES-CBC") or
            integrity in ("HMAC-MD5", "HMAC-SHA1") or
            (ike_version == 1 and exchange_mode == "aggressive")
        )
        reasons = []
        if dh_group_num in (1, 2, 5):
            reasons.append(f"Legacy DH Group {dh_group_num} (< 112 bits)")
        if encryption in ("3DES-CBC", "DES-CBC"):
            reasons.append(f"Deprecated cipher {encryption} (Sweet32 / short key)")
        if integrity in ("HMAC-MD5", "HMAC-SHA1"):
            reasons.append(f"Weak hash {integrity}")
        if ike_version == 1 and exchange_mode == "aggressive":
            reasons.append("IKEv1 Aggressive Mode PSK cleartext exposure")

        return TestbedProfile(
            session_id=session_id,
            ike_version=ike_version,
            exchange_mode=exchange_mode,
            mode=mode,
            ip_version=ip_version,
            encryption=encryption,
            integrity=integrity,
            dh_group_num=dh_group_num,
            dh_group_name=dh_info["name"],
            pfs_enabled=pfs_enabled,
            traffic_type=traffic_type,
            expected_security_label="vulnerable" if is_vuln else "secure",
            vulnerability_reason="; ".join(reasons) if reasons else None,
        )

    def generate_matrix(self) -> List[TestbedProfile]:
        """Generate testbed combinations across parameters."""
        matrix = []
        for ike_ver in [1, 2]:
            for mode in ["tunnel", "transport"]:
                for ip_ver in ["IPv4", "IPv6"]:
                    for dh in [1, 2, 5, 14, 19, 20, 31]:
                        for enc in ["AES-256-GCM", "AES-128-CBC", "3DES-CBC"]:
                            p = self.create_sample_profile(
                                session_id=f"tb-{ike_ver}-{dh}-{mode[:3]}-{enc[:3]}",
                                ike_version=ike_ver,
                                mode=mode,
                                ip_version=ip_ver,
                                encryption=enc,
                                dh_group_num=dh,
                            )
                            matrix.append(p)
        return matrix

    def generate_config(
        self,
        name: str = "custom-tunnel",
        ike_version: int = 2,
        cipher: str = "AES-256-GCM",
        dh_group: int = 14,
        hash_algo: str = "HMAC-SHA2-256",
        pfs: bool = True,
        mode: str = "tunnel",
        ip_version: str = "IPv4",
    ) -> TestbedProfile:
        """Generate dual configuration for specified parameters."""
        norm_cipher = cipher
        for k, v in CIPHER_MAP_SWAN.items():
            if v == cipher.lower() or k.lower() == cipher.lower():
                norm_cipher = k
                break
        return self.create_sample_profile(
            session_id=name,
            ike_version=ike_version,
            mode=mode,
            ip_version=ip_version,
            encryption=norm_cipher,
            dh_group_num=dh_group,
            pfs_enabled=pfs,
        )


IPsecTestbedGenerator = VPNTestbedGenerator
SUPPORTED_TESTBED_DH_GROUPS = TESTBED_DH_GROUPS
SUPPORTED_TESTBED_CIPHERS = list(CIPHER_MAP_SWAN.keys())
TestbedConfigRecord = TestbedProfile

