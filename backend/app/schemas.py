"""Pydantic schemas for data validation and API serialization."""
from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict


class UserRole(str, Enum):
    ANALYST = "analyst"
    ADMIN = "admin"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SECURE = "SECURE"


# -------------------------------------------------------------
# User & Auth Schemas
# -------------------------------------------------------------

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(..., min_length=6, max_length=100)
    role: Optional[UserRole] = UserRole.ANALYST


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(UserBase):
    id: int
    role: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class TokenPayload(BaseModel):
    sub: str
    user_id: int
    role: str
    exp: int


# -------------------------------------------------------------
# Upload Job Schemas
# -------------------------------------------------------------

class UploadJobResponse(BaseModel):
    id: str
    user_id: int
    filename: str
    file_type: str
    file_size_bytes: int
    status: str
    error_message: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# -------------------------------------------------------------
# VPN Session & Security Findings Schemas
# -------------------------------------------------------------

class VPNSessionResponse(BaseModel):
    id: int
    ike_version: int
    exchange_type: Optional[str] = None
    initiator_spi: Optional[str] = None
    responder_spi: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    cipher: Optional[str] = None
    dh_group: Optional[str] = None
    integrity_algo: Optional[str] = None
    prf_algo: Optional[str] = None
    auth_method: Optional[str] = None
    pfs_enabled: bool = False
    packet_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class FindingResponse(BaseModel):
    id: int
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    rfc_reference: Optional[str] = None
    evidence_json: Optional[str] = None
    remediation_hint: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RiskAssessmentResponse(BaseModel):
    id: int
    upload_id: str
    overall_score: float
    risk_level: str
    findings_summary_json: Optional[str] = None
    ml_anomaly_score: Optional[float] = None
    shap_top_features_json: Optional[str] = None
    config_diff_before: Optional[str] = None
    config_diff_after: Optional[str] = None
    executive_summary: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
