"""NetSentry AI - FastAPI Application Entrypoint."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db import init_db
from app.routers import auth

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("netsentry")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events for database initialization and cleanup."""
    logger.info("Initializing NetSentry AI services...")
    await init_db()
    yield
    logger.info("Shutting down NetSentry AI services...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "Production-Grade IPsec VPN Protocol Analyzer & Security Assessment Framework. "
        "Developed by Team Code Craft for Smart India Hackathon 2026 (SIH26160)."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
)

# Configure Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(auth.router, prefix=settings.API_V1_STR)


@app.get("/", tags=["General"])
async def root():
    """Welcome endpoint with API metadata and documentation links."""
    return {
        "name": settings.PROJECT_NAME,
        "status": "online",
        "version": "1.0.0",
        "description": "AI-powered IPsec VPN Protocol Analyzer (SIH26160)",
        "docs": "/docs",
        "redoc": "/redoc",
    }


@app.get("/health", tags=["General"])
@app.get(f"{settings.API_V1_STR}/health", tags=["General"])
async def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
