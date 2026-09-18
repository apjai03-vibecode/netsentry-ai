"""Stateful Finite State Machine (FSM) tracker for IKEv1 and IKEv2 handshakes."""
from enum import Enum
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class IKEv2State(str, Enum):
    IDLE = "IDLE"
    SA_INIT_REQ_SENT = "SA_INIT_REQ_SENT"
    SA_INIT_COMPLETED = "SA_INIT_COMPLETED"
    AUTH_REQ_SENT = "AUTH_REQ_SENT"
    ESTABLISHED = "ESTABLISHED"
    CHILD_SA = "CHILD_SA"
    TERMINATED_ABNORMALLY = "TERMINATED_ABNORMALLY"


class IKEv1State(str, Enum):
    IDLE = "IDLE"
    MM_SA_SENT = "MM_SA_SENT"           # Packet 1
    MM_SA_RCVD = "MM_SA_RCVD"           # Packet 2
    MM_KE_SENT = "MM_KE_SENT"           # Packet 3
    MM_KE_RCVD = "MM_KE_RCVD"           # Packet 4
    MM_AUTH_SENT = "MM_AUTH_SENT"       # Packet 5
    MM_ESTABLISHED = "MM_ESTABLISHED"   # Packet 6
    AM_INIT_SENT = "AM_INIT_SENT"       # Aggressive Mode Packet 1
    AM_RESP_RCVD = "AM_RESP_RCVD"       # Aggressive Mode Packet 2
    AM_ESTABLISHED = "AM_ESTABLISHED"   # Aggressive Mode Packet 3
    TRUNCATED = "TRUNCATED"


class IKEStateMachineTracker:
    """Tracks state transitions across sequential IKE messages to detect protocol deviations."""

    def __init__(self):
        self.state_v2 = IKEv2State.IDLE
        self.state_v1 = IKEv1State.IDLE
        self.packet_history: List[Dict[str, Any]] = []

    def reset(self):
        self.state_v2 = IKEv2State.IDLE
        self.state_v1 = IKEv1State.IDLE
        self.packet_history.clear()

    def process_packet(
        self,
        ike_version: int,
        exchange_type: str,
        msg_id: int,
        is_response: bool,
        is_initiator: bool,
    ) -> None:
        """Advance internal state machine based on incoming message metadata."""
        record = {
            "version": ike_version,
            "exchange": exchange_type,
            "msg_id": msg_id,
            "is_response": is_response,
            "is_initiator": is_initiator,
        }
        self.packet_history.append(record)

        if ike_version == 2:
            self._advance_v2(exchange_type, msg_id, is_response)
        elif ike_version == 1:
            self._advance_v1(exchange_type, is_response)

    def _advance_v2(self, exchange: str, msg_id: int, is_response: bool) -> None:
        """IKEv2 state transition logic."""
        exch_upper = exchange.upper()
        if "SA_INIT" in exch_upper or "34" in exch_upper:
            if not is_response:
                self.state_v2 = IKEv2State.SA_INIT_REQ_SENT
            else:
                self.state_v2 = IKEv2State.SA_INIT_COMPLETED
        elif "AUTH" in exch_upper or "35" in exch_upper:
            if not is_response:
                self.state_v2 = IKEv2State.AUTH_REQ_SENT
            else:
                self.state_v2 = IKEv2State.ESTABLISHED
        elif "CHILD_SA" in exch_upper or "CREATE_CHILD" in exch_upper:
            if self.state_v2 == IKEv2State.ESTABLISHED:
                self.state_v2 = IKEv2State.CHILD_SA

    def _advance_v1(self, exchange: str, is_response: bool) -> None:
        """IKEv1 Main Mode & Aggressive Mode state transition logic."""
        exch_upper = exchange.upper()
        pkt_num = len(self.packet_history)

        if "AGGRESSIVE" in exch_upper:
            if pkt_num == 1:
                self.state_v1 = IKEv1State.AM_INIT_SENT
            elif pkt_num == 2:
                self.state_v1 = IKEv1State.AM_RESP_RCVD
            elif pkt_num >= 3:
                self.state_v1 = IKEv1State.AM_ESTABLISHED
        else:
            # Main mode sequence (1 to 6)
            if pkt_num == 1:
                self.state_v1 = IKEv1State.MM_SA_SENT
            elif pkt_num == 2:
                self.state_v1 = IKEv1State.MM_SA_RCVD
            elif pkt_num == 3:
                self.state_v1 = IKEv1State.MM_KE_SENT
            elif pkt_num == 4:
                self.state_v1 = IKEv1State.MM_KE_RCVD
            elif pkt_num == 5:
                self.state_v1 = IKEv1State.MM_AUTH_SENT
            elif pkt_num >= 6:
                self.state_v1 = IKEv1State.MM_ESTABLISHED

    def evaluate_session(self, session_data: Any) -> List[Dict[str, Any]]:
        """
        Evaluate full session state integrity.
        Can consume ParsedVPNSessionData, VPNSession DB model, or a plain dict.
        """
        findings: List[Dict[str, Any]] = []

        # Extract normalized attributes
        if isinstance(session_data, dict):
            ike_version = session_data.get("ike_version", 2)
            exchange_types = session_data.get("exchange_types", [])
            packet_count = session_data.get("packet_count", 0)
            esp_packets = session_data.get("esp_packets", 0)
        else:
            ike_version = getattr(session_data, "ike_version", 2)
            et = getattr(session_data, "exchange_type", "") or ""
            ets = getattr(session_data, "exchange_types", []) or []
            if isinstance(ets, str):
                ets = [x.strip() for x in ets.split(",") if x.strip()]
            exchange_types = ets if ets else ([et] if et else [])
            packet_count = getattr(session_data, "packet_count", 0)
            esp_packets = getattr(session_data, "esp_packets", 0)

        et_str_upper = " ".join(exchange_types).upper()

        # -------------------------------------------------------------
        # 1. IKEv2 State Checks
        # -------------------------------------------------------------
        if ike_version == 2:
            has_init = any("INIT" in e.upper() for e in exchange_types)
            has_auth = any("AUTH" in e.upper() for e in exchange_types)

            # Check for Premature Handshake Termination
            if has_init and not has_auth and esp_packets == 0:
                findings.append({
                    "rule_id": "FSM-IKEV2-PREMATURE-TERMINATION",
                    "category": "State Sequencing",
                    "severity": "HIGH",
                    "title": "IKEv2 Handshake Truncated After IKE_SA_INIT",
                    "description": (
                        "The IKEv2 session initiated cryptographic exchange parameters via "
                        "IKE_SA_INIT, but never completed mutual identity authentication (IKE_AUTH). "
                        "This indicates negotiation failure, authentication mismatch, or network interception."
                    ),
                    "rfc_reference": "RFC 7296 Section 1.2",
                    "evidence_json": json.dumps({
                        "exchange_sequence": exchange_types,
                        "packet_count": packet_count,
                        "final_state": self.state_v2.value,
                    }),
                    "remediation_hint": (
                        "Verify peer authentication configurations, PSK matching, and certificate trust chains. "
                        "Check firewall UDP port 500/4500 drops after initial key exchange."
                    ),
                })

            # Check for Child SA / ESP data without Authentication
            if esp_packets > 0 and not has_auth:
                findings.append({
                    "rule_id": "FSM-IKEV2-MISSING-AUTH",
                    "category": "State Sequencing",
                    "severity": "CRITICAL",
                    "title": "ESP Data Observed Without Valid IKE_AUTH Handshake",
                    "description": (
                        "Encapsulating Security Payload (ESP) data was recorded without a prior completed "
                        "IKE_AUTH exchange in the capture session. This may indicate out-of-band SA injection "
                        "or incomplete capture analysis."
                    ),
                    "rfc_reference": "RFC 7296 Section 1.2",
                    "evidence_json": json.dumps({"esp_packets": esp_packets, "exchanges": exchange_types}),
                    "remediation_hint": "Ensure the entire IKE initiation and authentication sequence is captured.",
                })

        # -------------------------------------------------------------
        # 2. IKEv1 State Checks
        # -------------------------------------------------------------
        elif ike_version == 1:
            is_aggressive = any("AGGRESSIVE" in e.upper() for e in exchange_types)

            if is_aggressive:
                findings.append({
                    "rule_id": "FSM-IKEV1-CLEARTEXT-EXPOSURE",
                    "category": "State Sequencing",
                    "severity": "CRITICAL",
                    "title": "Cleartext Identity & PSK Hash Exposure in Aggressive Mode",
                    "description": (
                        "IKEv1 Aggressive Mode state progression sends peer identification and "
                        "pre-shared key hash payloads in the initial unencrypted message before a secure "
                        "cryptographic channel has been negotiated."
                    ),
                    "rfc_reference": "RFC 2409 Section 5.4",
                    "evidence_json": json.dumps({
                        "exchange_sequence": exchange_types,
                        "packets_seen": packet_count,
                    }),
                    "remediation_hint": "Disable Aggressive Mode on the gateway and transition to IKEv2.",
                })
            else:
                # Main Mode truncation check
                if 0 < packet_count < 6 and not any("QUICK" in e.upper() for e in exchange_types):
                    findings.append({
                        "rule_id": "FSM-IKEV1-TRUNCATED-MAIN-MODE",
                        "category": "State Sequencing",
                        "severity": "HIGH",
                        "title": "Incomplete IKEv1 Main Mode Handshake",
                        "description": (
                            f"IKEv1 Main Mode requires 6 sequential packets to establish Phase 1 SA. "
                            f"Only {packet_count} packet(s) were observed, indicating negotiation drop or timeout."
                        ),
                        "rfc_reference": "RFC 2409 Section 5.1",
                        "evidence_json": json.dumps({
                            "packet_count": packet_count,
                            "exchange_sequence": exchange_types,
                        }),
                        "remediation_hint": "Inspect peer logs to determine why Phase 1 authentication dropped.",
                    })

        # -------------------------------------------------------------
        # 3. Protocol Downgrade Signal
        # -------------------------------------------------------------
        has_v1 = ("MAIN" in et_str_upper) or ("AGGRESSIVE" in et_str_upper)
        has_v2 = ("INIT" in et_str_upper) or ("AUTH" in et_str_upper)
        has_v1_and_v2 = has_v1 and has_v2
        if has_v1_and_v2:
            findings.append({
                "rule_id": "FSM-DOWNGRADE-SIGNAL",
                "category": "Protocol Flow",
                "severity": "HIGH",
                "title": "Potential IKE Protocol Downgrade Attack Detected",
                "description": (
                    "Both IKEv2 and IKEv1 exchanges were observed concurrently between the same "
                    "endpoints. This pattern frequently indicates a downgrade attack or insecure fallback."
                ),
                "rfc_reference": "RFC 7296 Section 2.26",
                "evidence_json": json.dumps({"exchanges_detected": exchange_types}),
                "remediation_hint": "Configure endpoints to strictly reject fallback to IKEv1.",
            })

        return findings
