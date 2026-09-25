"""
Assessment Router for NetSentry.ai.

Endpoints for:
- Overall risk assessment and remediation diffs
- 7-Column Threat Matrix
- Protocol Identification with Observability taxonomy ([OBSERVED], [INFERRED], [NOT OBSERVABLE])
- Metadata Exposure & Side-Channel analysis
- Safe Remediation with Pre-Flight Checklist & Rollback Guidance
- Dual PDF Reports (Executive PDF & Technical Audit PDF)
"""

import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.db import get_db
from app.models import Finding, RiskAssessment, UploadJob, User, VPNSession
from app.reports.pdf_generator import PDFReportGenerator
from app.schemas import FindingResponse, RiskAssessmentResponse
from app.ml.ensemble import MLEnsemble
from app.engines.threat_matrix import ThreatMatrixEngine
from app.engines.protocol_ident import ProtocolIdentifier
from app.engines.metadata_exposure import MetadataExposureAnalyzer
from app.engines.remediation import RemediationGenerator

router = APIRouter(prefix="/assessments", tags=["Assessments"])
logger = logging.getLogger(__name__)


async def _get_authorized_job_and_assessment(job_id: str, db: AsyncSession, current_user: User):
    """Helper to fetch job and assessment with role/ownership enforcement."""
    stmt_job = select(UploadJob).where(UploadJob.id == job_id)
    res_job = await db.execute(stmt_job)
    job = res_job.scalar_one_or_none()

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Upload job not found.",
        )

    if current_user.role != "admin" and job.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this job assessment.",
        )

    stmt_assessment = select(RiskAssessment).where(RiskAssessment.upload_id == job_id)
    res_assessment = await db.execute(stmt_assessment)
    assessment = res_assessment.scalar_one_or_none()

    return job, assessment


@router.get(
    "/{job_id}",
    response_model=RiskAssessmentResponse,
    summary="Get overall risk assessment and remediation diffs for a job",
)
async def get_assessment(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve computed risk assessment, severity scores, and configuration diffs."""
    job, assessment = await _get_authorized_job_and_assessment(job_id, db, current_user)

    if not assessment:
        if job.status in ("queued", "processing"):
            raise HTTPException(
                status_code=status.HTTP_202_ACCEPTED,
                detail=f"Job is currently '{job.status}'. Assessment has not yet completed.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No risk assessment found for this job (job status: {job.status}).",
        )

    return assessment


@router.get(
    "/{job_id}/threat-matrix",
    summary="Get the 7-column Threat Matrix for a job",
)
async def get_threat_matrix(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns the consolidated 7-column Threat Matrix:
    Finding | Severity | Evidence | Impact | Confidence | Reference | Recommendation
    with Observability taxonomy tagging ([OBSERVED], [INFERRED], [NOT OBSERVABLE]).
    """
    job, assessment = await _get_authorized_job_and_assessment(job_id, db, current_user)

    # Check cached summary in assessment if present
    if assessment and assessment.findings_summary_json:
        try:
            parsed_summary = json.loads(assessment.findings_summary_json)
            if "threat_matrix" in parsed_summary:
                return parsed_summary["threat_matrix"]
        except Exception:
            pass

    # Build dynamically from findings & sessions
    stmt_findings = select(Finding).where(Finding.upload_id == job_id).order_by(Finding.id)
    res_findings = await db.execute(stmt_findings)
    findings_list = res_findings.scalars().all()

    stmt_sessions = select(VPNSession).where(VPNSession.upload_id == job_id)
    res_sessions = await db.execute(stmt_sessions)
    sessions_list = res_sessions.scalars().all()

    rule_findings_dicts = [
        {
            "id": f"FIND-{f.id}",
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "evidence": f.evidence_json or f.description,
            "reference": f.rfc_reference or "RFC 8247",
            "recommendation": f.remediation_hint or "Upgrade to recommended RFC baseline",
        }
        for f in findings_list
    ]

    rep_session = None
    if sessions_list:
        rep_session = max(
            sessions_list,
            key=lambda s: (
                1 if getattr(s, "exchange_type", "") and getattr(s, "exchange_type", "") != "Unknown" else 0,
                getattr(s, "packet_count", 0) or 0
            )
        )
    proto_ident_result = None
    if rep_session:
        proto_analyzer = ProtocolIdentifier()
        proto_ident_result = proto_analyzer.analyze_session(rep_session).dict()

    meta_analyzer = MetadataExposureAnalyzer()
    meta_result = meta_analyzer.analyze_sessions(sessions_list).dict()

    tm_engine = ThreatMatrixEngine()
    matrix_result = tm_engine.generate_matrix(
        rule_findings=rule_findings_dicts,
        protocol_ident=proto_ident_result,
        metadata_exposure=meta_result,
    )
    return matrix_result.dict()


@router.get(
    "/{job_id}/protocol-ident",
    summary="Get Protocol Identification & Observability taxonomy breakdown",
)
async def get_protocol_identification(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns protocol identification and characteristics strictly tagged with:
    [OBSERVED], [INFERRED], or [NOT OBSERVABLE].
    """
    job, assessment = await _get_authorized_job_and_assessment(job_id, db, current_user)

    stmt_sessions = select(VPNSession).where(VPNSession.upload_id == job_id)
    res_sessions = await db.execute(stmt_sessions)
    sessions_list = res_sessions.scalars().all()

    rep_session = sessions_list[0] if sessions_list else None
    if not rep_session:
        return {"session_id": "none", "characteristics": [], "taxonomy_summary": {"observed": 0, "inferred": 0, "not_observable": 0}}

    proto_analyzer = ProtocolIdentifier()
    result = proto_analyzer.analyze_session(rep_session)
    return result.dict()


@router.get(
    "/{job_id}/metadata-exposure",
    summary="Get Metadata Exposure and Traffic Analysis vulnerability assessment",
)
async def get_metadata_exposure(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Returns endpoint leakage, port exposure, SPI tracking, and side-channel leakage scoring."""
    job, assessment = await _get_authorized_job_and_assessment(job_id, db, current_user)

    stmt_sessions = select(VPNSession).where(VPNSession.upload_id == job_id)
    res_sessions = await db.execute(stmt_sessions)
    sessions_list = res_sessions.scalars().all()

    meta_analyzer = MetadataExposureAnalyzer()
    result = meta_analyzer.analyze_sessions(sessions_list)
    return result.dict()


@router.get(
    "/{job_id}/remediation",
    summary="Get safe remediation package (diffs, pre-flight checklist, and rollback guidance)",
)
async def get_remediation_package(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Returns strongSwan & Cisco configuration diffs, pre-flight checklist, and rollback steps."""
    job, assessment = await _get_authorized_job_and_assessment(job_id, db, current_user)

    stmt_findings = select(Finding).where(Finding.upload_id == job_id).order_by(Finding.id)
    res_findings = await db.execute(stmt_findings)
    findings_list = res_findings.scalars().all()

    stmt_sessions = select(VPNSession).where(VPNSession.upload_id == job_id)
    res_sessions = await db.execute(stmt_sessions)
    sessions_list = res_sessions.scalars().all()

    rep_session = sessions_list[0] if sessions_list else None
    findings_dicts = [{"rule_id": f.rule_id, "severity": f.severity, "title": f.title} for f in findings_list]

    remediation = RemediationGenerator.generate_all_remediations(rep_session, findings_dicts)
    return remediation


@router.get(
    "/{job_id}/pdf",
    summary="Download Executive or Technical PDF audit report",
)
async def download_pdf_report(
    job_id: str,
    report_type: str = Query("executive", pattern="^(executive|technical)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Download either an Executive Summary PDF or a comprehensive Technical Audit PDF.
    Parameter report_type: 'executive' (default) or 'technical'.
    """
    job, assessment = await _get_authorized_job_and_assessment(job_id, db, current_user)

    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment data not yet available for PDF generation.",
        )

    stmt_findings = select(Finding).where(Finding.upload_id == job_id).order_by(Finding.id)
    res_findings = await db.execute(stmt_findings)
    findings_list = res_findings.scalars().all()

    stmt_sessions = select(VPNSession).where(VPNSession.upload_id == job_id)
    res_sessions = await db.execute(stmt_sessions)
    sessions_list = res_sessions.scalars().all()
    rep_session = None
    if sessions_list:
        rep_session = max(
            sessions_list,
            key=lambda s: (
                1 if getattr(s, "exchange_type", "") and getattr(s, "exchange_type", "") != "Unknown" else 0,
                getattr(s, "packet_count", 0) or 0
            )
        )

    findings_dicts = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "category": f.category,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "rfc_reference": f.rfc_reference,
            "remediation_hint": f.remediation_hint,
        }
        for f in findings_list
    ]

    job_info = {
        "id": job.id,
        "filename": job.filename,
        "created_at": job.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if job.created_at else "N/A",
        "file_size_bytes": job.file_size_bytes,
    }

    assessment_data = {
        "overall_score": assessment.overall_score,
        "risk_level": assessment.risk_level,
        "executive_summary": assessment.executive_summary or "",
        "config_diff_before": assessment.config_diff_before or "",
        "config_diff_after": assessment.config_diff_after or "",
    }

    # Generate Threat Matrix
    proto_ident_result = ProtocolIdentifier().analyze_session(rep_session).model_dump() if rep_session else None
    meta_result = MetadataExposureAnalyzer().analyze_sessions(sessions_list).model_dump()
    tm_result = ThreatMatrixEngine().generate_matrix(
        rule_findings=findings_dicts,
        protocol_ident=proto_ident_result,
        metadata_exposure=meta_result,
    ).model_dump()

    remediations = RemediationGenerator.generate_all_remediations(rep_session, findings_dicts)

    if report_type == "technical":
        pdf_bytes = PDFReportGenerator.generate_technical_pdf(
            job_info=job_info,
            assessment_data=assessment_data,
            threat_matrix=tm_result,
            protocol_ident=proto_ident_result,
            metadata_exposure=meta_result,
            remediations=remediations,
        )
        report_label = "Technical-Audit"
    else:
        pdf_bytes = PDFReportGenerator.generate_executive_pdf(
            job_info=job_info,
            assessment_data=assessment_data,
            threat_matrix=tm_result,
            findings=findings_dicts,
        )
        report_label = "Executive-Brief"

    filename_safe = job.filename.replace(" ", "_").replace("/", "_")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="NetSentry-{report_label}-{job_id[:8]}-{filename_safe}.pdf"',
            "Content-Type": "application/pdf",
        },
    )


@router.get(
    "/{job_id}/executive-pdf",
    summary="Download Executive PDF audit brief",
)
async def download_executive_pdf(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Direct route for downloading Executive Brief PDF."""
    return await download_pdf_report(job_id=job_id, report_type="executive", db=db, current_user=current_user)


@router.get(
    "/{job_id}/technical-pdf",
    summary="Download Technical PDF audit report",
)
async def download_technical_pdf(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Direct route for downloading Technical Audit PDF."""
    return await download_pdf_report(job_id=job_id, report_type="technical", db=db, current_user=current_user)
