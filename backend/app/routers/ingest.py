"""Ingestion API Router: File uploads, magic-byte validation, encryption, and queue dispatch."""
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
from typing import List, Optional
import uuid

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.config import settings
from app.core.crypto import encrypt_bytes
from app.db import get_db
from app.models import UploadJob, User, VPNSession
from app.schemas import UploadJobResponse, VPNSessionResponse
from app.worker import dispatch_pcap_job

router = APIRouter(prefix="/ingest", tags=["Ingestion"])

# PCAP & PCAPNG Magic Bytes (4 bytes)
PCAP_MAGIC_BYTES = {
    b"\xd4\xc3\xb2\xa1": "pcap",       # standard microsecond, little-endian
    b"\xa1\xb2\xc3\xd4": "pcap",       # standard microsecond, big-endian
    b"\x4d\x3c\xb2\xa1": "pcap",       # nanosecond, little-endian
    b"\xa1\xb2\x3c\x4d": "pcap",       # nanosecond, big-endian
    b"\x0a\x0d\x0d\x0a": "pcapng",     # PCAP-NG Section Header Block
}


def detect_file_type(header: bytes, filename: str) -> Optional[str]:
    """Inspect magic bytes and filename to determine valid file format."""
    # Check binary PCAP/PCAPNG magic bytes
    if len(header) >= 4:
        magic = header[:4]
        if magic in PCAP_MAGIC_BYTES:
            return PCAP_MAGIC_BYTES[magic]

    # Check for text-based VPN configuration files
    lower_fn = filename.lower()
    if lower_fn.endswith((".conf", ".cfg", ".txt")):
        try:
            # Must be valid UTF-8 or ASCII text
            header.decode("utf-8")
            return "config"
        except UnicodeDecodeError:
            return None

    return None


@router.post(
    "/upload",
    response_model=UploadJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Upload PCAP/PCAPNG or VPN configuration file"
)
async def upload_capture_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Ingest a packet capture or VPN config:
    - Enforces 50MB file size limit
    - Validates PCAP/PCAPNG magic bytes or config encoding
    - Computes SHA-256 checksum
    - Encrypts file at rest (Fernet AES-256)
    - Enqueues background parsing pipeline
    """
    job_id = str(uuid.uuid4())
    upload_dir = Path(settings.UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)
    encrypted_path = upload_dir / f"{job_id}.enc"

    hasher = hashlib.sha256()
    total_size = 0
    first_chunk = True
    detected_type: Optional[str] = None

    chunks: List[bytes] = []
    chunk_size = 1024 * 1024  # 1MB chunks

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break

        total_size += len(chunk)
        if total_size > settings.MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)}MB"
            )

        if first_chunk:
            first_chunk = False
            detected_type = detect_file_type(chunk[:1024], file.filename)
            if not detected_type:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "Invalid file format. Uploaded file must be a valid PCAP/PCAPNG "
                        "capture (magic bytes verified) or a recognized VPN configuration file."
                    )
                )

        hasher.update(chunk)
        chunks.append(chunk)

    if total_size == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty."
        )

    # Combine bytes and encrypt to disk
    full_content = b"".join(chunks)
    ciphertext = encrypt_bytes(full_content)

    with open(encrypted_path, "wb") as f_out:
        f_out.write(ciphertext)

    # Compute retention timestamp
    retention_expires = datetime.now(timezone.utc) + timedelta(hours=settings.RETENTION_HOURS)

    # Persist UploadJob record
    upload_job = UploadJob(
        id=job_id,
        user_id=current_user.id,
        filename=file.filename,
        file_type=detected_type,
        file_size_bytes=total_size,
        file_hash_sha256=hasher.hexdigest(),
        storage_path=str(encrypted_path),
        status="queued",
        retention_expires_at=retention_expires,
    )
    db.add(upload_job)
    await db.commit()
    await db.refresh(upload_job)

    # Dispatch async parsing worker
    dispatch_pcap_job(job_id, str(encrypted_path), background_tasks)

    return upload_job


@router.get(
    "/jobs/{job_id}",
    response_model=UploadJobResponse,
    summary="Get status of an upload job"
)
async def get_job_status(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve status and metadata for a specific upload job."""
    stmt = select(UploadJob).where(UploadJob.id == job_id)
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Upload job not found."
        )

    # Non-admins can only view their own jobs
    if current_user.role != "admin" and job.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this job."
        )

    return job


@router.get(
    "/jobs/{job_id}/sessions",
    response_model=List[VPNSessionResponse],
    summary="Get extracted VPN sessions for an upload job"
)
async def get_job_sessions(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve parsed VPN sessions associated with an upload job."""
    # Check job ownership
    stmt_job = select(UploadJob).where(UploadJob.id == job_id)
    res_job = await db.execute(stmt_job)
    job = res_job.scalar_one_or_none()

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Upload job not found."
        )

    if current_user.role != "admin" and job.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this job."
        )

    stmt_sessions = select(VPNSession).where(VPNSession.upload_id == job_id)
    result = await db.execute(stmt_sessions)
    return result.scalars().all()
