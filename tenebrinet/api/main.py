# tenebrinet/api/main.py
"""
FastAPI application for TenebriNET REST API.

Provides REST endpoints for accessing honeypot data and managing services.
"""
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from tenebrinet import __version__
from tenebrinet.api.routes import attacks, health
from tenebrinet.core.database import init_db
from tenebrinet.core.logger import configure_logger


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.

    Handles startup and shutdown events.
    """
    # Startup
    configure_logger(log_level="INFO", log_format="json")
    await init_db()
    yield
    # Shutdown
    pass


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application instance.
    """
    app = FastAPI(
        title="TenebriNET API",
        description=(
            "REST API for the TenebriNET Intelligent Honeypot Infrastructure. "
            "Provides access to attack data, credentials, sessions, and "
            "statistics collected by the honeypot services."
        ),
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    app.include_router(health.router)
    app.include_router(attacks.router, prefix="/api/v1")

    return app


# Create the application instance
app = create_app()


@app.get("/", tags=["root"])
async def root() -> dict:
    """
    Root endpoint.

    Returns basic API information.
    """
    return {
        "name": "TenebriNET API",
        "version": __version__,
        "description": "Intelligent Honeypot Infrastructure",
        "docs": "/docs",
    }
