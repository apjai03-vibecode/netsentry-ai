"""Application Configuration Settings."""
import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment or defaults."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    PROJECT_NAME: str = "NetSentry AI"
    API_V1_STR: str = "/api"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Security & JWT
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY", 
        "netsentry-super-secret-key-change-in-production-sih26160-2026"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # Database
    # Defaults to PostgreSQL, but can be set to SQLite for local standalone development
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://netsentry:netsentry123@localhost:5432/netsentry_db"
    )

    # Redis & Background Workers
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Ingestion & Retention Policies
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "temp_uploads")
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    RETENTION_HOURS: int = 24  # Auto-delete raw packet captures after 24 hours

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
    ]


settings = Settings()
