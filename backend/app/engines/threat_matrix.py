"""
Threat Matrix Engine for NetSentry.ai.

Generates a unified 7-column Threat Matrix:
Finding | Severity | Evidence | Impact | Confidence | Reference | Recommendation

Consolidates outputs from:
- Deterministic RFC Rule Engine (RFC 8247, RFC 8221, RFC 7296, NIST SP 800-57)
- Stateful FSM Engine (state sequence anomalies, retransmission bursts, incomplete handshakes)
- Protocol Identification & Observability Engine (weak/inferred modes, cleartext parameters)
- Metadata Exposure Engine (endpoint leakage, timing side-channels, NAT traversal)
- Encrypted Traffic ML Classifier & Anomaly Detector (high-risk applications, entropy anomalies)
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.engines.protocol_ident import ObservabilityStatus


class ThreatMatrixEntry(BaseModel):
    """Represents a single row in the 7-column Threat Matrix."""
    finding_id: str
    finding: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    evidence: str
    impact: str
    confidence: str  # HIGH, MEDIUM, LOW
    reference: str  # RFC / NIST standard citation
    recommendation: str
    observability: str = "OBSERVED"  # OBSERVED, INFERRED, NOT_OBSERVABLE
    category: str = "CRYPTOGRAPHIC"  # CRYPTOGRAPHIC, STATE_MACHINE, METADATA, TRAFFIC_ANOMALY, POLICY


class ThreatMatrixSummary(BaseModel):
    """Aggregate statistics for the Threat Matrix."""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    observed_count: int = 0
    inferred_count: int = 0
    not_observable_count: int = 0


class ThreatMatrixResult(BaseModel):
    """Complete Threat Matrix assessment result."""
    entries: List[ThreatMatrixEntry] = Field(default_factory=list)
    summary: ThreatMatrixSummary = Field(default_factory=ThreatMatrixSummary)


class ThreatMatrixEngine:
    """Consolidates findings into a standardized 7-column Threat Matrix."""

    SEVERITY_ORDER = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFORMATIONAL": 1,
        "INFO": 1,
    }

    def generate_matrix(
        self,
        rule_findings: Optional[List[Dict[str, Any]]] = None,
        fsm_results: Optional[List[Dict[str, Any]]] = None,
        protocol_ident: Optional[Dict[str, Any]] = None,
        metadata_exposure: Optional[Dict[str, Any]] = None,
        ml_anomalies: Optional[List[Dict[str, Any]]] = None,
        traffic_classifications: Optional[List[Dict[str, Any]]] = None,
    ) -> ThreatMatrixResult:
        """Build the consolidated 7-column Threat Matrix from all subsystem outputs."""
        entries: List[ThreatMatrixEntry] = []
        rule_findings = rule_findings or []
        fsm_results = fsm_results or []

        # 1. Ingest Deterministic Rule Engine Findings
        for idx, rf in enumerate(rule_findings):
            fid = rf.get("id") or f"RULE-{idx+1:03d}"
            rule_id = rf.get("rule_id", fid)
            title = rf.get("title") or rf.get("description", "Cryptographic Compliance Violation")
            severity = str(rf.get("severity", "MEDIUM")).upper()
            if severity == "INFO":
                severity = "INFORMATIONAL"

            evidence = rf.get("evidence", "Identified in SA proposal or transform negotiation")
            reference = rf.get("reference") or rf.get("standard") or "RFC 8247 / RFC 8221"
            recommendation = rf.get("recommendation", "Upgrade cryptographic parameters to modern RFC baseline")

            # Determine impact based on finding type
            impact = self._derive_crypto_impact(title, severity)

            # Rule findings directly observed in IKE SA negotiation payloads have HIGH confidence
            confidence = "HIGH"
            observability = "OBSERVED"

            entries.append(ThreatMatrixEntry(
                finding_id=f"TM-{rule_id}",
                finding=title,
                severity=severity,
                evidence=str(evidence),
                impact=impact,
                confidence=confidence,
                reference=str(reference),
                recommendation=str(recommendation),
                observability=observability,
                category="CRYPTOGRAPHIC",
            ))

        # 2. Ingest Stateful FSM Results & Anomalies
        for idx, fsm in enumerate(fsm_results):
            session_id = fsm.get("session_id", f"session-{idx}")
            anomalies = fsm.get("anomalies", [])
            state = fsm.get("final_state", "UNKNOWN")
            handshake_complete = fsm.get("handshake_completed", False)

            for aidx, anomaly in enumerate(anomalies):
                anom_desc = anomaly if isinstance(anomaly, str) else anomaly.get("description", str(anomaly))
                anom_type = anomaly.get("type", "STATE_ANOMALY") if isinstance(anomaly, dict) else "STATE_ANOMALY"

                severity = "HIGH" if "unexpected" in anom_desc.lower() or "violation" in anom_desc.lower() else "MEDIUM"
                impact = "Potential state injection, incomplete tunnel establishment, or handshake desynchronization."
                confidence = "HIGH" if "payload" in anom_desc.lower() or "transition" in anom_desc.lower() else "MEDIUM"

                entries.append(ThreatMatrixEntry(
                    finding_id=f"TM-FSM-{idx+1:02d}-{aidx+1:02d}",
                    finding=f"FSM Anomaly in Session {session_id[:8]}: {anom_desc}",
                    severity=severity,
                    evidence=f"Session state machine reached {state}; Anomaly: {anom_desc}",
                    impact=impact,
                    confidence=confidence,
                    reference="RFC 7296 Section 1.2 / RFC 2409 Section 5",
                    recommendation="Review initiator/responder state machine timing, firewall drop policies, and retransmission thresholds.",
                    observability="OBSERVED",
                    category="STATE_MACHINE",
                ))

            if not handshake_complete and not anomalies:
                # Incomplete handshake without explicit anomaly
                entries.append(ThreatMatrixEntry(
                    finding_id=f"TM-FSM-INC-{idx+1:02d}",
                    finding=f"Incomplete IKE Handshake in Session {session_id[:8]}",
                    severity="LOW",
                    evidence=f"Session terminated at state {state} before completing SA negotiation.",
                    impact="SA was never fully established; encrypted Child SA data transfer did not commence.",
                    confidence="HIGH",
                    reference="RFC 7296 Section 2",
                    recommendation="Verify network connectivity between peers, pre-shared key validity, and proposal compatibility.",
                    observability="OBSERVED",
                    category="STATE_MACHINE",
                ))

        # 3. Ingest Protocol Identification & Observability findings
        if protocol_ident:
            characteristics = protocol_ident.get("characteristics", [])
            for c in characteristics:
                obs_status = c.get("observability", "OBSERVED")
                prop = c.get("property", "")
                val = c.get("value", "")
                evidence = c.get("evidence", "")

                # Flag insecure observed modes
                if "Aggressive Mode" in str(val):
                    entries.append(ThreatMatrixEntry(
                        finding_id="TM-PROTO-AGGRESSIVE",
                        finding="IKEv1 Aggressive Mode Observed in Cleartext Negotiation",
                        severity="HIGH",
                        evidence=evidence,
                        impact="Identity exposure: Peer identity and hash are transmitted in cleartext, susceptible to offline dictionary attack.",
                        confidence="HIGH",
                        reference="RFC 2409 Section 5.4 / RFC 8247 Section 4",
                        recommendation="Migrate to IKEv2 (RFC 7296) or restrict IKEv1 to Main Mode with strong authentication.",
                        observability="OBSERVED",
                        category="POLICY",
                    ))
                elif "Not Observable" in str(obs_status) and "Child SA Encryption" in prop:
                    # Informational boundary note
                    entries.append(ThreatMatrixEntry(
                        finding_id="TM-PROTO-CHILD-ENC-BOUNDARY",
                        finding="Child SA Encryption Cipher Not Observable from Passive PCAP",
                        severity="INFORMATIONAL",
                        evidence=evidence,
                        impact="Verification of ESP encryption parameters requires access to IKE_AUTH session secrets or device configuration.",
                        confidence="HIGH",
                        reference="RFC 7296 Section 1.2 (Encryption Boundary)",
                        recommendation="Audit responder and initiator swanctl.conf / Cisco crypto map configs directly for ESP ciphersuites.",
                        observability="NOT_OBSERVABLE",
                        category="POLICY",
                    ))

        # 4. Ingest Metadata Exposure Warnings
        if metadata_exposure:
            findings = metadata_exposure.get("findings", [])
            for f in findings:
                entries.append(ThreatMatrixEntry(
                    finding_id=f.get("finding_id", "TM-META-EXP"),
                    finding=f.get("title", "Metadata Exposure Detected"),
                    severity=f.get("severity", "MEDIUM"),
                    evidence=f.get("evidence", "Traffic analysis of outer packet headers"),
                    impact=f.get("impact", "Traffic analysis allows passive eavesdroppers to infer communication activity."),
                    confidence="HIGH",
                    reference="RFC 4301 Section 4.4.1 / NIST SP 800-77",
                    recommendation=f.get("recommendation", "Consider Traffic Flow Confidentiality (TFC) padding per RFC 4303."),
                    observability="OBSERVED",
                    category="METADATA",
                ))

        # 5. Ingest ML Anomalies & Encrypted Traffic Classifications
        if ml_anomalies:
            for idx, ma in enumerate(ml_anomalies):
                anom_type = ma.get("anomaly_type", "Behavioral Anomaly")
                desc = ma.get("description", "Statistically significant flow deviation detected")
                score = ma.get("anomaly_score", 0.0)
                sev = "HIGH" if score > 0.8 else "MEDIUM"

                entries.append(ThreatMatrixEntry(
                    finding_id=f"TM-ML-{idx+1:02d}",
                    finding=f"Encrypted Flow Anomaly: {anom_type}",
                    severity=sev,
                    evidence=f"Anomaly score: {score:.2f}; Features: {desc}",
                    impact="Potential data exfiltration, covert tunneling, or burst activity deviating from standard IPsec profiles.",
                    confidence="MEDIUM",
                    reference="NIST SP 800-77 / ISO/IEC 27001 A.12.6",
                    recommendation="Inspect flow end-systems and verify matching security policy rules for unusual traffic bursts.",
                    observability="INFERRED",
                    category="TRAFFIC_ANOMALY",
                ))

        if traffic_classifications:
            for idx, tc in enumerate(traffic_classifications):
                risk = tc.get("risk_level", "LOW")
                pred_app = tc.get("predicted_application", "UNKNOWN")
                conf = tc.get("confidence", 0.0)

                if risk in ("HIGH", "CRITICAL"):
                    entries.append(ThreatMatrixEntry(
                        finding_id=f"TM-APP-RISK-{idx+1:02d}",
                        finding=f"High-Risk Encrypted Application Inferred: {pred_app}",
                        severity=risk,
                        evidence=f"Inferred {pred_app} with {conf*100:.1f}% confidence based on packet size/IAT flow signature.",
                        impact="Encrypted tunnel carries traffic matching high-risk application signatures (e.g. bulk transfer or interactive shell).",
                        confidence="MEDIUM",
                        reference="NIST SP 800-77 Section 3.4",
                        recommendation="Enforce application-layer egress filtering and micro-segmentation inside the VPN tunnel.",
                        observability="INFERRED",
                        category="TRAFFIC_ANOMALY",
                    ))

        # Sort entries by severity descending
        entries.sort(key=lambda x: self.SEVERITY_ORDER.get(x.severity, 0), reverse=True)

        # Build summary
        summary = ThreatMatrixSummary(
            total_findings=len(entries),
            critical_count=sum(1 for e in entries if e.severity == "CRITICAL"),
            high_count=sum(1 for e in entries if e.severity == "HIGH"),
            medium_count=sum(1 for e in entries if e.severity == "MEDIUM"),
            low_count=sum(1 for e in entries if e.severity == "LOW"),
            info_count=sum(1 for e in entries if e.severity in ("INFORMATIONAL", "INFO")),
            observed_count=sum(1 for e in entries if e.observability == "OBSERVED"),
            inferred_count=sum(1 for e in entries if e.observability == "INFERRED"),
            not_observable_count=sum(1 for e in entries if e.observability == "NOT_OBSERVABLE"),
        )

        return ThreatMatrixResult(entries=entries, summary=summary)

    def _derive_crypto_impact(self, title: str, severity: str) -> str:
        """Generate precise technical impact for cryptographic findings."""
        t_lower = title.lower()
        if "3des" in t_lower or "des" in t_lower:
            return "Sweet32 collision attack vulnerability (CVE-2016-2183): 64-bit block size allows plaintext recovery after ~32GB of data."
        elif "md5" in t_lower or "sha-1" in t_lower or "sha1" in t_lower:
            return "Collision resistance compromised: Practical collision attacks undermine integrity and authentication assurances."
        elif "diffie-hellman" in t_lower or "dh group" in t_lower or "group 1" in t_lower or "group 2" in t_lower:
            return "Logjam attack vulnerability / weak key exchange: Modulus under 2048 bits susceptible to nation-state precomputation (NIST SP 800-57)."
        elif "aggressive" in t_lower:
            return "Cleartext hash transmission: Pre-shared key hash is transmitted in packet 2 without encryption, enabling offline dictionary attacks."
        elif "pfs" in t_lower:
            return "Lack of Forward Secrecy: Compromise of the long-term private key allows retrospective decryption of all past recorded Child SA traffic."
        elif severity == "CRITICAL":
            return "Complete cryptographic failure: Immediate risk of eavesdropping or session hijack."
        elif severity == "HIGH":
            return "Significant cryptographic degradation: Protocol does not meet baseline regulatory compliance (NIST / RFC)."
        else:
            return "Sub-optimal security configuration: Does not adhere to latest RFC 8247 recommendations."
