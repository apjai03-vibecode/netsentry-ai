"""
Remediation Engine for NetSentry.ai.

Generates safe before/after configuration diffs, pre-flight validation checklists,
and rollback guidance for strongSwan (swanctl.conf) and Cisco IOS-XE.
DOES NOT automatically apply configurations to production VPN gateways.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PreFlightCheckItem(BaseModel):
    """A single pre-flight validation step."""
    check_id: str
    category: str
    item: str
    verification_command: str
    risk_if_skipped: str


class RollbackGuidance(BaseModel):
    """Step-by-step rollback instructions and commands."""
    platform: str
    backup_command: str
    restore_command: str
    verification_command: str
    steps: List[str]


class RemediationPackage(BaseModel):
    """Complete remediation response including diffs, pre-flight, and rollback."""
    safety_notice: str
    swanctl_diff: Dict[str, str]
    cisco_diff: Dict[str, str]
    pre_flight_checklist: List[PreFlightCheckItem]
    rollback_guidance: Dict[str, RollbackGuidance]
    combined_before: str
    combined_after: str


class RemediationGenerator:
    """Generates before vs. after configuration diffs, validation checklists, and rollback plans."""

    SAFETY_NOTICE = (
        "SAFE REMEDIATION NOTICE: NetSentry generates hardened configuration diffs and validation "
        "checklists for administrator review. Automated direct deployment to live production network "
        "appliances is intentionally disabled to prevent unintended service disruption or cryptographic desynchronization."
    )

    @classmethod
    def get_preflight_checklist(cls) -> List[PreFlightCheckItem]:
        """Return standardized pre-flight interoperability checklist."""
        return [
            PreFlightCheckItem(
                check_id="CHK-01",
                category="Peer Capability",
                item="Verify remote peer supports IKEv2 and proposed AEAD algorithms (AES-GCM-256, DH Group 14/19)",
                verification_command="strongSwan: swanctl --stats | Cisco: show crypto ikev2 capabilities",
                risk_if_skipped="Handshake proposal mismatch (NO_PROPOSAL_CHOSEN); tunnel fails to establish.",
            ),
            PreFlightCheckItem(
                check_id="CHK-02",
                category="Firewall & NAT-T",
                item="Verify UDP port 500 and UDP port 4500 are permitted along the intermediate path",
                verification_command="nc -u -z -w 3 <peer_ip> 500 && nc -u -z -w 3 <peer_ip> 4500",
                risk_if_skipped="IKE_SA_INIT succeeds on port 500, but IKE_AUTH or ESP drops if port 4500 is blocked.",
            ),
            PreFlightCheckItem(
                check_id="CHK-03",
                category="Configuration Backup",
                item="Create an offline backup copy of current active configuration",
                verification_command="strongSwan: cp /etc/swanctl/conf.d/vpn-tunnel.conf /etc/swanctl/conf.d/vpn-tunnel.conf.bak | Cisco: copy running-config flash:backup-config.cfg",
                risk_if_skipped="Unable to instantly revert if peer configuration cannot be synchronized.",
            ),
            PreFlightCheckItem(
                check_id="CHK-04",
                category="Maintenance Window",
                item="Schedule maintenance window for re-keying and SA re-establishment",
                verification_command="N/A - Operational Procedure",
                risk_if_skipped="Active IPsec SA will be terminated; inflight user sessions may be reset.",
            ),
            PreFlightCheckItem(
                check_id="CHK-05",
                category="Authentication Sync",
                item="Ensure PSK secrets or PKI CA trust chains match exactly on both peers",
                verification_command="strongSwan: swanctl --list-creds | Cisco: show crypto ikev2 sa",
                risk_if_skipped="AUTHENTICATION_FAILED notification during IKE_AUTH exchange.",
            ),
        ]

    @classmethod
    def get_rollback_guidance(cls) -> Dict[str, RollbackGuidance]:
        """Return step-by-step rollback procedures for each supported platform."""
        return {
            "strongswan": RollbackGuidance(
                platform="strongSwan (swanctl)",
                backup_command="cp /etc/swanctl/conf.d/vpn-tunnel.conf /etc/swanctl/conf.d/vpn-tunnel.conf.bak",
                restore_command="cp /etc/swanctl/conf.d/vpn-tunnel.conf.bak /etc/swanctl/conf.d/vpn-tunnel.conf && swanctl --load-all",
                verification_command="swanctl --list-sas",
                steps=[
                    "1. Terminate failing SA: swanctl --terminate --ike netsentry-vpn",
                    "2. Restore original config: cp /etc/swanctl/conf.d/vpn-tunnel.conf.bak /etc/swanctl/conf.d/vpn-tunnel.conf",
                    "3. Reload configuration: swanctl --load-all",
                    "4. Re-initiate baseline tunnel: swanctl --initiate --child net-traffic",
                    "5. Verify SA status: swanctl --list-sas",
                ],
            ),
            "cisco": RollbackGuidance(
                platform="Cisco IOS-XE",
                backup_command="copy running-config flash:pre-remediation.cfg",
                restore_command="configure replace flash:pre-remediation.cfg force",
                verification_command="show crypto session detail",
                steps=[
                    "1. Enter privileged EXEC mode: enable",
                    "2. Replace running config from backup: configure replace flash:pre-remediation.cfg force",
                    "3. Clear stale crypto sessions: clear crypto session",
                    "4. Verify tunnel restoration: show crypto session detail",
                    "5. Verify interface routing: ping <remote_tunnel_ip>",
                ],
            ),
        }

    @classmethod
    def generate_swanctl_diff(cls, session_data: Any, findings: List[Dict[str, Any]]) -> Dict[str, str]:
        """Generate strongSwan (swanctl.conf) Before and After configuration snippets."""
        cipher = getattr(session_data, "cipher", "3des") or "3des"
        dh_num = getattr(session_data, "dh_group_num", 2) or 2
        integ = getattr(session_data, "integrity_algo", "sha1") or "sha1"
        ike_ver = getattr(session_data, "ike_version", 1) or 1
        pfs = getattr(session_data, "pfs_enabled", False)

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
        """Generate Cisco IOS-XE Before and After configuration snippets."""
        before_cisco = """! --- BEFORE (INSECURE CISCO IOS-XE CONFIGURATION) ---
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

        after_cisco = """! +++ AFTER (HARDENED CISCO IOS-XE IKEv2 CONFIGURATION) +++
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
        """
        Generate strongSwan and Cisco diffs along with pre-flight checklist and rollback guidance.
        Backwards-compatible dictionary with enhanced safe remediation metadata.
        """
        swanctl = cls.generate_swanctl_diff(session_data, findings)
        cisco = cls.generate_cisco_diff(session_data, findings)
        checklist = [item.model_dump() for item in cls.get_preflight_checklist()]
        rollback = {k: v.model_dump() for k, v in cls.get_rollback_guidance().items()}

        combined_before = f"# --- strongSwan Configuration ---\n{swanctl['before']}\n\n! --- Cisco IOS-XE Configuration ---\n{cisco['before']}"
        combined_after = f"# +++ strongSwan Remediated +++\n{swanctl['after']}\n\n! +++ Cisco IOS-XE Remediated +++\n{cisco['after']}"

        return {
            "swanctl": swanctl,
            "cisco": cisco,
            "combined_before": combined_before,
            "combined_after": combined_after,
            "safety_notice": cls.SAFETY_NOTICE,
            "pre_flight_checklist": checklist,
            "rollback_guidance": rollback,
        }
