"""SQLAlchemy Database Models for NetSentry AI."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from app.db import Base


def utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    """User account model with role-based access control."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="analyst", nullable=False)  # 'analyst' or 'admin'
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    uploads = relationship("UploadJob", back_populates="user", cascade="all, delete-orphan")


class UploadJob(Base):
    """Uploaded PCAP or VPN config job tracking."""
    __tablename__ = "upload_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    filename = Column(String(255), nullable=False)
    file_type = Column(String(20), nullable=False)  # 'pcap', 'pcapng', 'config'
    file_size_bytes = Column(Integer, nullable=False)
    file_hash_sha256 = Column(String(64), nullable=False)
    storage_path = Column(String(512), nullable=True)
    status = Column(String(20), default="queued", index=True, nullable=False)  # 'queued', 'processing', 'completed', 'failed'
    error_message = Column(Text, nullable=True)
    retention_expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    user = relationship("User", back_populates="uploads")
    sessions = relationship("VPNSession", back_populates="upload", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="upload", cascade="all, delete-orphan")
    assessment = relationship("RiskAssessment", back_populates="upload", uselist=False, cascade="all, delete-orphan")


class VPNSession(Base):
    """Parsed IKE / IPsec protocol handshake parameters."""
    __tablename__ = "vpn_sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    upload_id = Column(String(36), ForeignKey("upload_jobs.id", ondelete="CASCADE"), index=True, nullable=False)
    ike_version = Column(Integer, nullable=False)  # 1 or 2
    exchange_type = Column(String(64), nullable=True)  # e.g., 'IKE_SA_INIT', 'Main Mode'
    initiator_spi = Column(String(32), nullable=True)
    responder_spi = Column(String(32), nullable=True)
    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)
    src_port = Column(Integer, default=500)
    dst_port = Column(Integer, default=500)
    cipher = Column(String(64), nullable=True)  # e.g., 'AES-GCM-256', '3DES-CBC'
    dh_group = Column(String(64), nullable=True)  # e.g., 'Group 14 (2048-bit)'
    dh_group_num = Column(Integer, nullable=True)
    integrity_algo = Column(String(64), nullable=True)
    prf_algo = Column(String(64), nullable=True)
    auth_method = Column(String(64), nullable=True)
    pfs_enabled = Column(Boolean, default=False)
    lifetime_seconds = Column(Integer, nullable=True)
    esp_spi = Column(String(32), nullable=True)
    packet_count = Column(Integer, default=0)
    raw_metadata_json = Column(Text, nullable=True)  # Detailed parsed attributes
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    upload = relationship("UploadJob", back_populates="sessions")
    findings = relationship("Finding", back_populates="session", cascade="all, delete-orphan")


class Finding(Base):
    """Individual security vulnerability, RFC violation, or anomaly finding."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    upload_id = Column(String(36), ForeignKey("upload_jobs.id", ondelete="CASCADE"), index=True, nullable=False)
    session_id = Column(Integer, ForeignKey("vpn_sessions.id", ondelete="SET NULL"), index=True, nullable=True)
    rule_id = Column(String(64), index=True, nullable=False)
    category = Column(String(64), nullable=False)  # 'Cryptography', 'Protocol Flow', 'State Sequencing', 'Anomaly'
    severity = Column(String(20), index=True, nullable=False)  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    rfc_reference = Column(String(128), nullable=True)
    evidence_json = Column(Text, nullable=True)  # Context, offending values, packet offsets
    remediation_hint = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    upload = relationship("UploadJob", back_populates="findings")
    session = relationship("VPNSession", back_populates="findings")


class RiskAssessment(Base):
    """Aggregated risk score and remediation report."""
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    upload_id = Column(String(36), ForeignKey("upload_jobs.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    overall_score = Column(Float, nullable=False)  # 0.0 - 100.0 (Higher = Higher Risk)
    risk_level = Column(String(20), nullable=False)  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SECURE'
    findings_summary_json = Column(Text, nullable=True)
    ml_anomaly_score = Column(Float, nullable=True)
    shap_top_features_json = Column(Text, nullable=True)
    config_diff_before = Column(Text, nullable=True)
    config_diff_after = Column(Text, nullable=True)
    executive_summary = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    upload = relationship("UploadJob", back_populates="assessment")
