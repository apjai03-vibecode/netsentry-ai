"""Assessment Router: Endpoints for risk scores, executive PDF reports, and remediation diffs."""
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.db import get_db
from app.models import Finding, RiskAssessment, UploadJob, User
from app.reports.pdf_generator import PDFReportGenerator
from app.schemas import FindingResponse, RiskAssessmentResponse
from app.ml.ensemble import MLEnsemble

router = APIRouter(prefix="/assessments", tags=["Assessments"])
logger = logging.getLogger(__name__)


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
    "/{job_id}/pdf",
    summary="Download comprehensive executive audit report as PDF",
)
async def download_pdf_report(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate and stream a professional executive PDF audit report with RFC citations and diffs."""
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
            detail="Access denied to this job report.",
        )

    stmt_assessment = select(RiskAssessment).where(RiskAssessment.upload_id == job_id)
    res_assessment = await db.execute(stmt_assessment)
    assessment = res_assessment.scalar_one_or_none()

    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment data not yet available for PDF generation.",
        )

    stmt_findings = select(Finding).where(Finding.upload_id == job_id).order_by(Finding.id)
    res_findings = await db.execute(stmt_findings)
    findings_list = res_findings.scalars().all()

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

    ml_metrics = None
    try:
        ensemble = MLEnsemble.get_instance()
        ml_metrics = ensemble.get_metrics()
    except Exception as e:
        logger.debug(f"Could not load ML metrics for PDF: {e}")

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

    pdf_bytes = PDFReportGenerator.generate(
        job_info=job_info,
        assessment_data=assessment_data,
        findings=findings_dicts,
        ml_metrics=ml_metrics,
    )

    filename_safe = job.filename.replace(" ", "_").replace("/", "_")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="NetSentry-Audit-{job_id[:8]}-{filename_safe}.pdf"',
            "Content-Type": "application/pdf",
        },
    )
