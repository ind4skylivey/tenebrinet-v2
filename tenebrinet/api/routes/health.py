# tenebrinet/api/routes/health.py
"""
Health check API endpoints.

Provides endpoints for monitoring service health and status.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from tenebrinet import __version__
from tenebrinet.api.schemas import HealthResponse, ServiceStatus
from tenebrinet.core.database import get_db_session


router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_check(
    db: AsyncSession = Depends(get_db_session),
) -> HealthResponse:
    """
    Health check endpoint.

    Returns the overall health status of the application,
    including database connectivity and service status.
    """
    # Check database connection
    db_status = "connected"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "disconnected"

    # TODO: Get actual service status from service registry
    # For now, return placeholder values
    services = [
        ServiceStatus(
            service="ssh_honeypot",
            running=False,
            host="0.0.0.0",
            port=2222,
            connections=0,
        ),
        ServiceStatus(
            service="http_honeypot",
            running=False,
            host="0.0.0.0",
            port=8080,
            connections=0,
        ),
        ServiceStatus(
            service="ftp_honeypot",
            running=False,
            host="0.0.0.0",
            port=2121,
            connections=0,
        ),
    ]

    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        version=__version__,
        timestamp=datetime.now(timezone.utc),
        services=services,
        database=db_status,
    )


@router.get("/ready")
async def readiness_check(
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """
    Kubernetes-style readiness probe.

    Returns 200 if the application is ready to accept traffic.
    """
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception as e:
        return {"status": "not_ready", "error": str(e)}


@router.get("/live")
async def liveness_check() -> dict:
    """
    Kubernetes-style liveness probe.

    Returns 200 if the application is alive.
    """
    return {"status": "alive", "timestamp": datetime.now(timezone.utc)}
