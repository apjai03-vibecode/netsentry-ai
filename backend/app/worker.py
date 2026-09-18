"""Celery background worker and job orchestration for PCAP processing."""
import asyncio
import json
import logging
from pathlib import Path
from typing import Optional
from celery import Celery
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.crypto import decrypt_file_to_bytes
from app.db import AsyncSessionLocal
from app.models import UploadJob, VPNSession
from app.parsers.ike_parser import IKEParser

logger = logging.getLogger(__name__)

# Initialize Celery app instance
celery_app = Celery(
    "netsentry",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,  # 5 minutes max per PCAP
)


async def _execute_pcap_pipeline(job_id: str, encrypted_path: str) -> None:
    """Core async routine to decrypt, parse PCAP, and persist VPN session records."""
    async with AsyncSessionLocal() as session:
        try:
            # 1. Update status to processing
            stmt_status = (
                update(UploadJob)
                .where(UploadJob.id == job_id)
                .values(status="processing")
            )
            await session.execute(stmt_status)
            await session.commit()

            # 2. Decrypt raw bytes in memory (zero plaintext write to disk)
            raw_pcap_bytes = decrypt_file_to_bytes(encrypted_path)

            # 3. Parse IKE / IPsec sessions
            parsed_sessions = IKEParser.parse_pcap(raw_pcap_bytes)

            # 4. Insert VPNSession records
            for ps in parsed_sessions:
                vpn_session = VPNSession(
                    upload_id=job_id,
                    ike_version=ps.ike_version,
                    exchange_type=", ".join(ps.exchange_types) if ps.exchange_types else "Unknown",
                    initiator_spi=ps.initiator_spi,
                    responder_spi=ps.responder_spi,
                    src_ip=ps.src_ip,
                    dst_ip=ps.dst_ip,
                    src_port=ps.src_port,
                    dst_port=ps.dst_port,
                    cipher=ps.cipher,
                    dh_group=ps.dh_group,
                    dh_group_num=ps.dh_group_num,
                    integrity_algo=ps.integrity_algo,
                    prf_algo=ps.prf_algo,
                    auth_method=ps.auth_method,
                    pfs_enabled=ps.pfs_enabled,
                    esp_spi=ps.esp_spi,
                    packet_count=ps.packet_count,
                    raw_metadata_json=json.dumps(ps.raw_metadata),
                )
                session.add(vpn_session)

            # 5. Mark job as completed
            stmt_done = (
                update(UploadJob)
                .where(UploadJob.id == job_id)
                .values(status="completed")
            )
            await session.execute(stmt_done)
            await session.commit()
            logger.info(f"Successfully processed PCAP for Job {job_id} ({len(parsed_sessions)} sessions discovered)")

        except Exception as e:
            logger.error(f"Error processing PCAP for Job {job_id}: {e}", exc_info=True)
            await session.rollback()
            stmt_err = (
                update(UploadJob)
                .where(UploadJob.id == job_id)
                .values(status="failed", error_message=str(e))
            )
            await session.execute(stmt_err)
            await session.commit()


@celery_app.task(name="tasks.process_pcap", bind=True)
def process_pcap_task(self, job_id: str, encrypted_path: str):
    """Celery background worker entrypoint."""
    logger.info(f"[Celery] Processing PCAP task for Job {job_id}...")
    asyncio.run(_execute_pcap_pipeline(job_id, encrypted_path))
    return {"status": "success", "job_id": job_id}


import socket
from urllib.parse import urlparse


def is_redis_available(redis_url: str = settings.REDIS_URL, timeout: float = 0.2) -> bool:
    """Fast probe to check if Redis broker is reachable without blocking."""
    try:
        parsed = urlparse(redis_url)
        host = parsed.hostname or "localhost"
        port = parsed.port or 6379
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def dispatch_pcap_job(job_id: str, encrypted_path: str, background_tasks=None) -> None:
    """Dispatch PCAP processing via Celery or fallback to FastAPI BackgroundTasks if Redis is unavailable."""
    dispatched_celery = False
    if is_redis_available():
        try:
            res = process_pcap_task.delay(job_id, encrypted_path)
            logger.info(f"Job {job_id} successfully queued with Celery task ID: {res.id}")
            dispatched_celery = True
        except Exception as e:
            logger.warning(f"Celery queue dispatch failed ({e}). Falling back to in-process worker.")
    else:
        logger.info(f"Redis broker offline. Dispatching Job {job_id} via in-process background worker.")

    if not dispatched_celery:
        if background_tasks:
            background_tasks.add_task(_execute_pcap_pipeline, job_id, encrypted_path)
        else:
            asyncio.create_task(_execute_pcap_pipeline(job_id, encrypted_path))
