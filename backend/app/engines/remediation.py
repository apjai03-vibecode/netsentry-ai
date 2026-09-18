"""Remediation Engine: Generates before/after configuration snippets for strongSwan and Cisco IOS."""
from typing import Any, Dict, List, Optional


class RemediationGenerator:
    """Generates before vs. after configuration diffs for VPN appliances based on session findings."""

    @classmethod
    def generate_swanctl_diff(cls, session_data: Any, findings: List[Dict[str, Any]]) -> Dict[str, str]:
        """Generate strongSwan (swanctl.conf) Before and After configuration snippets."""
        cipher = getattr(session_data, "cipher", "3des") or "3des"
        dh_num = getattr(session_data, "dh_group_num", 2) or 2
        dh_str = getattr(session_data, "dh_group", "modp1024") or "modp1024"
        integ = getattr(session_data, "integrity_algo", "sha1") or "sha1"
        ike_ver = getattr(session_data, "ike_version", 1) or 1
        pfs = getattr(session_data, "pfs_enabled", False)

        # Before Snippet (Insecure as detected)
        modp_name = f"modp{768 if dh_num == 1 else (1024 if dh_num == 2 else 1536)}" if dh_num in (1, 2, 5) else "modp1024"
        c_name = "3des" if "3DES" in cipher.upper() else ("des" if "DES" in cipher.upper() else "aes128")
        h_name = "md5" if "MD5" in integ.upper() else "sha1"

        before_snippet = f"""# --- BEFORE (INSECURE DETECTED CONFIGURATION) ---
# File: /etc/swanctl/conf.d/vpn-tunnel.conf
connections {{
    netsentry-vpn {{
        version = {ike_ver}
        proposals = {c_name}-{h_name}-{modp_name}
        aggressive = {'yes' if ike_ver == 1 else 'no'}
        local_addrs = 192.168.1.100
        remote_addrs = 198.51.100.1

        local {{
            auth = psk
            id = vpn-client@domain.internal
        }}
        remote {{
            auth = psk
        }}

        children {{
            net-traffic {{
                esp_proposals = {c_name}-{h_name}{f'-{modp_name}' if pfs else ''}
                mode = tunnel
                local_ts = 10.0.0.0/24
                remote_ts = 10.1.0.0/24
            }}
        }}
    }}
}}"""

        # After Snippet (RFC 8247 & RFC 8221 Hardened)
        after_snippet = """# +++ AFTER (HARDENED NETSENTRY REMEDIATION) +++
# File: /etc/swanctl/conf.d/vpn-tunnel.conf
connections {
    netsentry-vpn {
        version = 2
        # RFC 8247 Compliant: AEAD AES-GCM-256 with PRF-SHA256 and DH Group 14/19
        proposals = aes256gcm16-prfsha256-modp2048-ecp256, aes128gcm16-prfsha256-ecp256
        aggressive = no
        local_addrs = 192.168.1.100
        remote_addrs = 198.51.100.1

        local {
            auth = psk
            id = vpn-client@domain.internal
        }
        remote {
            auth = psk
        }

        children {
            net-traffic {
                # AEAD AES-GCM-256 with mandatory Perfect Forward Secrecy (MODP-2048 / ECP-256)
                esp_proposals = aes256gcm16-modp2048, aes256gcm16-ecp256
                mode = tunnel
                dpd_action = restart
                local_ts = 10.0.0.0/24
                remote_ts = 10.1.0.0/24
            }
        }
    }
}"""
        return {"before": before_snippet, "after": after_snippet}

    @classmethod
    def generate_cisco_diff(cls, session_data: Any, findings: List[Dict[str, Any]]) -> Dict[str, str]:
        """Generate Cisco IOS Before and After configuration snippets."""
        before_cisco = """! --- BEFORE (INSECURE CISCO IOS CONFIGURATION) ---
! Legacy IKEv1 with weak DH Group and deprecated 3DES/MD5
crypto isakmp policy 10
 encr 3des
 hash md5
 authentication pre-share
 group 2
 lifetime 86400
!
crypto ipsec transform-set LEGACY_TRANSFORM esp-3des esp-md5-hmac
 mode tunnel
!
crypto map VPN_MAP 10 ipsec-isakmp
 set peer 198.51.100.1
 set transform-set LEGACY_TRANSFORM
 ! Notice: PFS is not enabled here
 match address 101"""

        after_cisco = """! +++ AFTER (HARDENED CISCO IOS IKEv2 CONFIGURATION) +++
! Modern RFC 8247 / RFC 8221 hardened IKEv2 configuration
crypto ikev2 proposal NETSENTRY_PROPOSAL
 encryption aes-gcm-256
 prf sha256
 group 19 14
!
crypto ikev2 policy NETSENTRY_POLICY
 proposal NETSENTRY_PROPOSAL
!
crypto ipsec transform-set SECURE_TRANSFORM esp-gcm 256
 mode tunnel
!
crypto ipsec profile NETSENTRY_PROFILE
 set transform-set SECURE_TRANSFORM
 set pfs group14
 set ikev2-policy NETSENTRY_POLICY
!
interface Tunnel1
 ip address 10.255.255.1 255.255.255.252
 tunnel source GigabitEthernet0/0
 tunnel destination 198.51.100.1
 tunnel mode ipsec ipv4
 tunnel protection ipsec profile NETSENTRY_PROFILE"""

        return {"before": before_cisco, "after": after_cisco}

    @classmethod
    def generate_all_remediations(cls, session_data: Any, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate both strongSwan and Cisco IOS diff snippets."""
        swanctl = cls.generate_swanctl_diff(session_data, findings)
        cisco = cls.generate_cisco_diff(session_data, findings)

        combined_before = f"# --- strongSwan Configuration ---\n{swanctl['before']}\n\n! --- Cisco IOS Configuration ---\n{cisco['before']}"
        combined_after = f"# +++ strongSwan Remediated +++\n{swanctl['after']}\n\n! +++ Cisco IOS Remediated +++\n{cisco['after']}"

        return {
            "swanctl": swanctl,
            "cisco": cisco,
            "combined_before": combined_before,
            "combined_after": combined_after,
        }
