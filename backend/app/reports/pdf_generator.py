"""Executive PDF Report Generator for NetSentry AI using ReportLab."""
from datetime import datetime, timezone
import io
import json
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

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
)


def get_severity_color(severity: str) -> colors.Color:
    """Return color matching NetSentry light design system."""
    sev = severity.upper()
    if sev == "CRITICAL":
        return colors.HexColor("#EF4444")  # Red
    elif sev == "HIGH":
        return colors.HexColor("#F97316")  # Amber / Orange
    elif sev == "MEDIUM":
        return colors.HexColor("#EAB308")  # Yellow
    elif sev == "LOW":
        return colors.HexColor("#3B82F6")  # Blue
    return colors.HexColor("#10B981")       # Green / Info / Secure


class PDFReportGenerator:
    """Generates professional executive audit reports for SIH26160 judges and security teams."""

    @classmethod
    def generate(
        cls,
        job_info: Dict[str, Any],
        assessment_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        ml_metrics: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """Generate PDF report bytes from audit data."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        accent_color = colors.HexColor("#4F46E5")  # Soft Indigo
        dark_text = colors.HexColor("#0F172A")    # Slate 900
        muted_text = colors.HexColor("#64748B")   # Slate 500
        card_bg = colors.HexColor("#F8FAFC")      # Slate 50

        # Custom typography
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=accent_color,
            fontName="Helvetica-Bold",
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=muted_text,
            fontName="Helvetica",
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontSize=13,
            leading=17,
            textColor=dark_text,
            fontName="Helvetica-Bold",
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=dark_text,
            fontName="Helvetica",
        )
        code_style = ParagraphStyle(
            "CodeBlock",
            parent=styles["Code"],
            fontSize=7.5,
            leading=10,
            fontName="Courier",
            textColor=colors.HexColor("#1E293B"),
        )

        story = []

        # -------------------------------------------------------------
        # Header Banner
        # -------------------------------------------------------------
        story.append(Paragraph("NetSentry AI — Protocol Security Assessment", title_style))
        story.append(Paragraph("Smart India Hackathon 2026 | Problem Statement SIH26160 | Team Code Craft", subtitle_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1.5, color=accent_color, spaceAfter=14))

        # -------------------------------------------------------------
        # Metadata Card
        # -------------------------------------------------------------
        job_id = job_info.get("id", "N/A")
        filename = job_info.get("filename", "capture.pcap")
        created_at = job_info.get("created_at", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))

        meta_data = [
            [
                Paragraph("<b>Audit Target:</b>", body_style),
                Paragraph(str(filename), body_style),
                Paragraph("<b>Job Reference:</b>", body_style),
                Paragraph(str(job_id)[:16] + "...", body_style),
            ],
            [
                Paragraph("<b>Assessment Date:</b>", body_style),
                Paragraph(str(created_at)[:19], body_style),
                Paragraph("<b>Audit Engines:</b>", body_style),
                Paragraph("RFC 8247 + FSM + XGBoost", body_style),
            ],
        ]
        meta_table = Table(meta_data, colWidths=[1.3 * inch, 2.3 * inch, 1.3 * inch, 2.3 * inch])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), card_bg),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 14))

        # -------------------------------------------------------------
        # Risk Score Gauge Block
        # -------------------------------------------------------------
        score = float(assessment_data.get("overall_score", 0.0))
        level = str(assessment_data.get("risk_level", "SECURE")).upper()
        exec_summary = assessment_data.get("executive_summary", "Assessment completed successfully.")

        score_color = get_severity_color(level)

        score_table_data = [
            [
                Paragraph(f"<font size=32 color='{score_color.hexval()}'><b>{score}</b></font><font size=12 color='#64748B'>/100</font><br/><b><font color='{score_color.hexval()}'>{level} RISK</font></b>", body_style),
                Paragraph(f"<b>Executive Assessment:</b><br/>{exec_summary}", body_style),
            ]
        ]
        score_table = Table(score_table_data, colWidths=[2.2 * inch, 5.0 * inch])
        score_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), card_bg),
            ("BOX", (0, 0), (-1, -1), 1.0, score_color),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 14))

        # -------------------------------------------------------------
        # Security Findings Table
        # -------------------------------------------------------------
        story.append(Paragraph(f"Security Findings & RFC Non-Conformances ({len(findings)} Detected)", h2_style))

        if findings:
            findings_header = [
                Paragraph("<b>Rule ID</b>", body_style),
                Paragraph("<b>Severity</b>", body_style),
                Paragraph("<b>Description & Title</b>", body_style),
                Paragraph("<b>RFC Standard</b>", body_style),
            ]
            findings_rows = [findings_header]

            for f in findings:
                sev = f.get("severity", "MEDIUM")
                s_color = get_severity_color(sev)
                findings_rows.append([
                    Paragraph(f"<b>{f.get('rule_id', '')}</b>", body_style),
                    Paragraph(f"<font color='{s_color.hexval()}'><b>{sev}</b></font>", body_style),
                    Paragraph(f"<b>{f.get('title', '')}</b><br/>{f.get('description', '')[:140]}...", body_style),
                    Paragraph(f.get("rfc_reference", "RFC 7296"), body_style),
                ])

            findings_table = Table(findings_rows, colWidths=[1.4 * inch, 1.0 * inch, 3.5 * inch, 1.3 * inch])
            findings_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F6")),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(findings_table)
        else:
            story.append(Paragraph("<i>No security findings or RFC violations detected.</i>", body_style))

        story.append(Spacer(1, 14))

        # -------------------------------------------------------------
        # Actionable Remediation (Before vs After)
        # -------------------------------------------------------------
        diff_before = assessment_data.get("config_diff_before", "")
        diff_after = assessment_data.get("config_diff_after", "")

        if diff_before and diff_after:
            story.append(Paragraph("Actionable Remediation: Recommended Hardened Configuration", h2_style))
            remed_data = [
                [
                    Paragraph("<b>Remediated Configuration (swanctl.conf / Cisco IOS):</b>", body_style),
                ],
                [
                    Paragraph(f"<pre>{diff_after[:900]}</pre>", code_style),
                ]
            ]
            remed_table = Table(remed_data, colWidths=[7.2 * inch])
            remed_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(KeepTogether(remed_table))
            story.append(Spacer(1, 14))

        # -------------------------------------------------------------
        # Machine Learning Validation Summary
        # -------------------------------------------------------------
        if ml_metrics:
            story.append(Paragraph("Machine Learning Validation Baseline", h2_style))
            ml_summary_text = (
                f"<b>Model:</b> XGBoost Classifier (100 estimators, max depth 4) + Isolation Forest | "
                f"<b>Accuracy:</b> {ml_metrics.get('accuracy', 1.0) * 100:.1f}% | "
                f"<b>Precision:</b> {ml_metrics.get('precision', 1.0) * 100:.1f}% | "
                f"<b>Recall:</b> {ml_metrics.get('recall', 1.0) * 100:.1f}% | "
                f"<b>FPR:</b> {ml_metrics.get('false_positive_rate', 0.0) * 100:.1f}%"
            )
            story.append(Paragraph(ml_summary_text, body_style))
            story.append(Spacer(1, 10))

        # Footer note
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=6))
        story.append(Paragraph("Confidential — Generated by NetSentry AI Security Assessment Platform (SIH26160)", subtitle_style))

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
