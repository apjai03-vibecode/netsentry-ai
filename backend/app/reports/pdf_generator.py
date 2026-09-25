"""
Dual PDF Report Generator for NetSentry.ai.

Generates:
1. Executive PDF: High-level risk score, executive summary, Observability breakdown, top findings, pre-flight checklist.
2. Technical PDF: Deep technical audit report with 7-column Threat Matrix, Protocol Identification taxonomy,
   Metadata Exposure analysis, 14 Flow Features & Encrypted Traffic classification, and safe remediation diffs with rollback guidance.
"""

from datetime import datetime, timezone
import io
import json
from typing import Any, Dict, List, Optional, Union

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def get_severity_color(severity: str) -> colors.Color:
    """Return color matching NetSentry design system."""
    sev = str(severity).upper()
    if sev == "CRITICAL":
        return colors.HexColor("#EF4444")  # Red
    elif sev == "HIGH":
        return colors.HexColor("#F97316")  # Amber / Orange
    elif sev == "MEDIUM":
        return colors.HexColor("#EAB308")  # Yellow
    elif sev == "LOW":
        return colors.HexColor("#3B82F6")  # Blue
    return colors.HexColor("#10B981")       # Green / Info / Secure


def get_observability_color(status: str) -> colors.Color:
    """Return color for Observability taxonomy tag."""
    s = str(status).upper()
    if "OBSERVED" in s and "NOT" not in s:
        return colors.HexColor("#0D9488")  # Teal / Cyan
    elif "INFERRED" in s:
        return colors.HexColor("#8B5CF6")  # Purple
    return colors.HexColor("#64748B")       # Slate / Gray for Not Observable


class PDFReportGenerator:
    """Generates professional executive and technical audit reports for SIH26160 judges and security teams."""

    @classmethod
    def _create_styles(cls):
        styles = getSampleStyleSheet()
        accent_color = colors.HexColor("#4F46E5")  # Soft Indigo
        dark_text = colors.HexColor("#0F172A")    # Slate 900
        muted_text = colors.HexColor("#64748B")   # Slate 500

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=accent_color,
            fontName="Helvetica-Bold",
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontSize=9.5,
            leading=13,
            textColor=muted_text,
            fontName="Helvetica",
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=dark_text,
            fontName="Helvetica-Bold",
            spaceBefore=10,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=11.5,
            textColor=dark_text,
            fontName="Helvetica",
        )
        body_small = ParagraphStyle(
            "BodySmall",
            parent=styles["Normal"],
            fontSize=7.5,
            leading=10,
            textColor=dark_text,
            fontName="Helvetica",
        )
        code_style = ParagraphStyle(
            "CodeBlock",
            parent=styles["Code"],
            fontSize=7,
            leading=9.5,
            fontName="Courier",
            textColor=colors.HexColor("#1E293B"),
        )
        return {
            "title": title_style,
            "subtitle": subtitle_style,
            "h2": h2_style,
            "body": body_style,
            "small": body_small,
            "code": code_style,
            "accent": accent_color,
            "muted": muted_text,
            "dark": dark_text,
            "card_bg": colors.HexColor("#F8FAFC"),
        }

    @classmethod
    def generate_executive_pdf(
        cls,
        job_info: Dict[str, Any],
        assessment_data: Dict[str, Any],
        threat_matrix: Optional[Dict[str, Any]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> bytes:
        """Generate high-level Executive PDF Report."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )
        s = cls._create_styles()
        story = []

        # Header
        story.append(Paragraph("NetSentry AI — Executive Protocol Security Assessment", s["title"]))
        story.append(Paragraph("Smart India Hackathon 2026 | Problem Statement SIH26160 | Executive Audit Brief", s["subtitle"]))
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=1.5, color=s["accent"], spaceAfter=10))

        # Metadata Card
        filename = job_info.get("filename", "capture.pcap")
        job_id = str(job_info.get("id", "N/A"))
        created_at = str(job_info.get("created_at", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")))[:19]

        meta_table = Table([
            [
                Paragraph("<b>Audit Target:</b>", s["body"]),
                Paragraph(str(filename), s["body"]),
                Paragraph("<b>Job ID:</b>", s["body"]),
                Paragraph(f"{job_id[:16]}...", s["body"]),
            ],
            [
                Paragraph("<b>Date:</b>", s["body"]),
                Paragraph(created_at, s["body"]),
                Paragraph("<b>Engines:</b>", s["body"]),
                Paragraph("RFC 8247 + FSM + ThreatMatrix + ML", s["body"]),
            ],
        ], colWidths=[1.2 * inch, 2.4 * inch, 1.2 * inch, 2.4 * inch])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), s["card_bg"]),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # Score & Summary Block
        score = float(assessment_data.get("overall_score", 0.0))
        level = str(assessment_data.get("risk_level", "SECURE")).upper()
        exec_summary = assessment_data.get("executive_summary", "Cryptographic evaluation completed successfully.")
        score_color = get_severity_color(level)

        score_table = Table([
            [
                Paragraph(f"<font size=28 color='{score_color.hexval()}'><b>{score:.0f}</b></font><font size=10 color='#64748B'>/100</font><br/><b><font color='{score_color.hexval()}'>{level} RISK</font></b>", s["body"]),
                Paragraph(f"<b>Executive Summary:</b><br/>{exec_summary}", s["body"]),
            ]
        ], colWidths=[2.0 * inch, 5.2 * inch])
        score_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), s["card_bg"]),
            ("BOX", (0, 0), (-1, -1), 1.0, score_color),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 10))

        # Observability Taxonomy Summary Card
        tm_summary = threat_matrix.get("summary", {}) if threat_matrix else {}
        obs_c = tm_summary.get("observed_count", 0)
        inf_c = tm_summary.get("inferred_count", 0)
        not_c = tm_summary.get("not_observable_count", 0)

        obs_table = Table([
            [
                Paragraph("<b>Taxonomy Breakdown:</b>", s["body"]),
                Paragraph(f"<font color='#0D9488'><b>[OBSERVED]: {obs_c}</b></font> (Direct cleartext RFC evidence)", s["body"]),
                Paragraph(f"<font color='#8B5CF6'><b>[INFERRED]: {inf_c}</b></font> (Heuristic / ML statistical model)", s["body"]),
                Paragraph(f"<font color='#64748B'><b>[NOT OBSERVABLE]: {not_c}</b></font> (Protected inside ESP/AUTH)", s["body"]),
            ]
        ], colWidths=[1.8 * inch, 1.8 * inch, 1.8 * inch, 1.8 * inch])
        obs_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ]))
        story.append(obs_table)
        story.append(Spacer(1, 10))

        # Top Threat Matrix Findings (Critical & High only)
        story.append(Paragraph("Priority Findings & Strategic Risks", s["h2"]))
        entries = threat_matrix.get("entries", []) if threat_matrix else []
        priority_entries = [e for e in entries if e.get("severity") in ("CRITICAL", "HIGH")][:5]

        if not priority_entries and findings:
            # Fallback to findings list if threat matrix not populated
            priority_entries = [
                {
                    "finding": f.get("title", ""),
                    "severity": f.get("severity", "MEDIUM"),
                    "reference": f.get("rfc_reference", "RFC 8247"),
                    "recommendation": f.get("remediation_hint", ""),
                }
                for f in findings if f.get("severity") in ("CRITICAL", "HIGH")
            ][:5]

        if priority_entries:
            rows = [[
                Paragraph("<b>Finding</b>", s["small"]),
                Paragraph("<b>Severity</b>", s["small"]),
                Paragraph("<b>Reference</b>", s["small"]),
                Paragraph("<b>Strategic Recommendation</b>", s["small"]),
            ]]
            for p in priority_entries:
                sev = p.get("severity", "HIGH")
                col = get_severity_color(sev)
                rows.append([
                    Paragraph(f"<b>{p.get('finding', '')[:65]}</b>", s["small"]),
                    Paragraph(f"<font color='{col.hexval()}'><b>{sev}</b></font>", s["small"]),
                    Paragraph(p.get("reference", "RFC 8247")[:25], s["small"]),
                    Paragraph(p.get("recommendation", "")[:120], s["small"]),
                ])
            ptable = Table(rows, colWidths=[2.3 * inch, 0.9 * inch, 1.4 * inch, 2.6 * inch])
            ptable.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F6")),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(ptable)
        else:
            story.append(Paragraph("<i>No critical or high-severity vulnerabilities identified. Cryptographic posture aligns with modern RFC baseline.</i>", s["body"]))

        story.append(Spacer(1, 10))

        # Safe Remediation & Pre-Flight Overview
        story.append(Paragraph("Remediation Governance & Pre-Flight Validation", s["h2"]))
        story.append(Paragraph(
            "NetSentry adheres to a zero-risk automated deployment policy: safe configuration templates are generated "
            "for strongSwan (swanctl) and Cisco IOS-XE, but require explicit operator review. Before applying changes, "
            "the following pre-flight checks are mandatory:", s["body"]
        ))
        story.append(Spacer(1, 4))

        checklist = [
            "1. <b>Peer Compatibility:</b> Verify remote gateway supports IKEv2 and proposed AEAD algorithms (AES-GCM-256).",
            "2. <b>Port & NAT-T Path:</b> Confirm UDP 500 and UDP 4500 transit end-to-end firewalls.",
            "3. <b>Configuration Snapshot:</b> Save active running config to offline backup prior to applying changes.",
            "4. <b>Maintenance Window:</b> Schedule change window; active Child SAs will terminate during cipher renegotiation.",
        ]
        for c in checklist:
            story.append(Paragraph(c, s["small"]))

        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=4))
        story.append(Paragraph("Confidential — Generated by NetSentry AI Platform (SIH26160 | Executive Report)", s["subtitle"]))

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    @classmethod
    def generate_technical_pdf(
        cls,
        job_info: Dict[str, Any],
        assessment_data: Dict[str, Any],
        threat_matrix: Optional[Dict[str, Any]] = None,
        protocol_ident: Optional[Dict[str, Any]] = None,
        metadata_exposure: Optional[Dict[str, Any]] = None,
        flow_classification: Optional[List[Dict[str, Any]]] = None,
        remediations: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """Generate comprehensive Technical PDF Report with complete Threat Matrix and Diff details."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=28,
            leftMargin=28,
            topMargin=28,
            bottomMargin=28,
        )
        s = cls._create_styles()
        story = []

        # Technical Header
        story.append(Paragraph("NetSentry AI — Technical Cryptographic Audit & Protocol Analysis", s["title"]))
        story.append(Paragraph("SIH26160 Comprehensive Assessment | Deterministic Rules + FSM + Threat Matrix + Encrypted Flow ML", s["subtitle"]))
        story.append(Spacer(1, 6))
        story.append(HRFlowable(width="100%", thickness=1.5, color=s["accent"], spaceAfter=8))

        # -------------------------------------------------------------
        # Section 1: Target & Session Overview
        # -------------------------------------------------------------
        story.append(Paragraph("1. Session Characteristics & Observability Baseline", s["h2"]))
        if protocol_ident:
            chars = protocol_ident.get("characteristics", [])
            p_rows = [[
                Paragraph("<b>Property</b>", s["small"]),
                Paragraph("<b>Value</b>", s["small"]),
                Paragraph("<b>Observability Status</b>", s["small"]),
                Paragraph("<b>Evidence & Source</b>", s["small"]),
            ]]
            for c in chars[:8]:
                obs = c.get("observability", "OBSERVED")
                ocol = get_observability_color(obs)
                p_rows.append([
                    Paragraph(f"<b>{c.get('property', '')}</b>", s["small"]),
                    Paragraph(str(c.get("value", ""))[:45], s["small"]),
                    Paragraph(f"<font color='{ocol.hexval()}'><b>[{obs}]</b></font>", s["small"]),
                    Paragraph(c.get("evidence", "")[:60], s["small"]),
                ])
            ptab = Table(p_rows, colWidths=[1.8 * inch, 1.8 * inch, 1.4 * inch, 2.4 * inch])
            ptab.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F6")),
                ("PADDING", (0, 0), (-1, -1), 3),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(ptab)
        story.append(Spacer(1, 8))

        # -------------------------------------------------------------
        # Section 2: Complete 7-Column Threat Matrix
        # -------------------------------------------------------------
        story.append(Paragraph("2. Threat Matrix (RFC Non-Conformances & Protocol Anomalies)", s["h2"]))
        entries = threat_matrix.get("entries", []) if threat_matrix else []
        if entries:
            tm_rows = [[
                Paragraph("<b>Finding</b>", s["small"]),
                Paragraph("<b>Sev</b>", s["small"]),
                Paragraph("<b>Evidence</b>", s["small"]),
                Paragraph("<b>Impact</b>", s["small"]),
                Paragraph("<b>Conf</b>", s["small"]),
                Paragraph("<b>Reference</b>", s["small"]),
                Paragraph("<b>Recommendation</b>", s["small"]),
            ]]
            for e in entries[:12]:
                sev = e.get("severity", "MEDIUM")
                scol = get_severity_color(sev)
                tm_rows.append([
                    Paragraph(f"<b>{e.get('finding', '')[:40]}</b>", s["small"]),
                    Paragraph(f"<font color='{scol.hexval()}'><b>{sev[:4]}</b></font>", s["small"]),
                    Paragraph(e.get("evidence", "")[:45], s["small"]),
                    Paragraph(e.get("impact", "")[:50], s["small"]),
                    Paragraph(e.get("confidence", "HIGH")[:3], s["small"]),
                    Paragraph(e.get("reference", "")[:18], s["small"]),
                    Paragraph(e.get("recommendation", "")[:55], s["small"]),
                ])
            tmtab = Table(tm_rows, colWidths=[1.4 * inch, 0.5 * inch, 1.2 * inch, 1.4 * inch, 0.5 * inch, 1.0 * inch, 1.4 * inch])
            tmtab.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F6")),
                ("PADDING", (0, 0), (-1, -1), 2.5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(tmtab)
        else:
            story.append(Paragraph("<i>No entries in Threat Matrix. All cryptographic checks passed.</i>", s["body"]))
        story.append(Spacer(1, 8))

        # -------------------------------------------------------------
        # Section 3: Metadata Exposure & Side-Channels
        # -------------------------------------------------------------
        if metadata_exposure:
            story.append(Paragraph("3. Metadata Exposure & Traffic Analysis Vulnerability", s["h2"]))
            leakage_score = metadata_exposure.get("leakage_score", 0.0)
            exposure_level = metadata_exposure.get("exposure_level", "LOW")
            meta_findings = metadata_exposure.get("findings", [])

            story.append(Paragraph(
                f"<b>Leakage Score:</b> {leakage_score:.1f}/100 ({exposure_level}) | "
                f"<b>Endpoints Leaked:</b> {metadata_exposure.get('endpoints_exposed', 0)} | "
                f"<b>NAT-T Migration:</b> {metadata_exposure.get('nat_t_detected', False)} | "
                f"<b>SPIs Exposed:</b> {len(metadata_exposure.get('spis_observed', []))}",
                s["body"]
            ))
            if meta_findings:
                for mf in meta_findings[:3]:
                    story.append(Paragraph(f"• <b>{mf.get('title', '')}:</b> {mf.get('impact', '')}", s["small"]))
            story.append(Spacer(1, 8))

        # -------------------------------------------------------------
        # Section 4: Encrypted Traffic Intelligence (14 Flow Features)
        # -------------------------------------------------------------
        if flow_classification:
            story.append(Paragraph("4. Encrypted Traffic Classification & Anomaly Detection", s["h2"]))
            fc_rows = [[
                Paragraph("<b>Predicted App</b>", s["small"]),
                Paragraph("<b>Confidence</b>", s["small"]),
                Paragraph("<b>Risk Level</b>", s["small"]),
                Paragraph("<b>Behavioral Indicators</b>", s["small"]),
            ]]
            for fc in flow_classification[:4]:
                r = fc.get("risk_level", "LOW")
                rcol = get_severity_color(r)
                fc_rows.append([
                    Paragraph(f"<b>{fc.get('predicted_application', 'UNKNOWN')}</b>", s["small"]),
                    Paragraph(f"{fc.get('confidence', 0.0)*100:.1f}%", s["small"]),
                    Paragraph(f"<font color='{rcol.hexval()}'><b>{r}</b></font>", s["small"]),
                    Paragraph(", ".join(fc.get("behavioral_indicators", []))[:70], s["small"]),
                ])
            fctab = Table(fc_rows, colWidths=[2.0 * inch, 1.0 * inch, 1.0 * inch, 3.4 * inch])
            fctab.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F6")),
                ("PADDING", (0, 0), (-1, -1), 3),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ]))
            story.append(fctab)
            story.append(Spacer(1, 8))

        # -------------------------------------------------------------
        # Section 5: Safe Remediation Diff & Rollback
        # -------------------------------------------------------------
        story.append(Paragraph("5. Hardened Configuration Remediation & Rollback Plan", s["h2"]))
        remed_data = remediations or {}
        diff_after = remed_data.get("swanctl", {}).get("after", "") or assessment_data.get("config_diff_after", "")

        if diff_after:
            remed_box = [
                [Paragraph("<b>Recommended strongSwan (swanctl.conf) Remediated Configuration:</b>", s["small"])],
                [Paragraph(f"<pre>{diff_after[:800]}</pre>", s["code"])],
            ]
            rtab = Table(remed_box, colWidths=[7.4 * inch])
            rtab.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(KeepTogether(rtab))
            story.append(Spacer(1, 6))

        # Rollback commands snippet
        rollback = remed_data.get("rollback_guidance", {})
        sw_rollback = rollback.get("strongswan", {})
        if sw_rollback:
            story.append(Paragraph(
                f"<b>Rollback Procedure:</b> Execute: <font color='#B91C1C'><code>{sw_rollback.get('restore_command', 'cp /etc/swanctl.conf.bak ...')}</code></font> "
                f"and verify status with: <code>{sw_rollback.get('verification_command', 'swanctl --list-sas')}</code>.",
                s["small"]
            ))

        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=4))
        story.append(Paragraph("Confidential — Generated by NetSentry AI Platform (SIH26160 | Technical Audit Report)", s["subtitle"]))

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    @classmethod
    def generate(
        cls,
        job_info: Dict[str, Any],
        assessment_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        ml_metrics: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """Default backwards-compatible generator delegating to Executive PDF."""
        return cls.generate_executive_pdf(job_info, assessment_data, findings=findings)
