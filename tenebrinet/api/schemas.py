# tenebrinet/api/schemas.py
"""
Pydantic schemas for API request/response validation.

Defines the data transfer objects used by the API endpoints.
"""
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# --- Attack Schemas ---


class AttackBase(BaseModel):
    """Base schema for attack data."""

    ip: str = Field(..., description="Source IP address")
    service: str = Field(..., description="Targeted service (ssh, http, ftp)")
    threat_type: Optional[str] = Field(
        None, description="ML-classified threat type"
    )
    confidence: Optional[float] = Field(
        None, description="ML classification confidence", ge=0.0, le=1.0
    )
    country: Optional[str] = Field(
        None, max_length=2, description="ISO country code"
    )
    asn: Optional[int] = Field(None, description="Autonomous System Number")


class AttackCreate(AttackBase):
    """Schema for creating a new attack record."""

    payload: Optional[dict] = Field(None, description="Attack payload data")


class AttackResponse(AttackBase):
    """Schema for attack response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime
    payload: Optional[dict] = None


class AttackListResponse(BaseModel):
    """Paginated list of attacks."""

    items: List[AttackResponse]
    total: int
    page: int
    per_page: int
    pages: int


# --- Credential Schemas ---


class CredentialResponse(BaseModel):
    """Schema for credential response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    attack_id: UUID
    username: str
    password: str
    success: bool


class CredentialListResponse(BaseModel):
    """List of credentials."""

    items: List[CredentialResponse]
    total: int


# --- Session Schemas ---


class SessionResponse(BaseModel):
    """Schema for session response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    attack_id: UUID
    start_time: datetime
    end_time: Optional[datetime] = None
    commands: Optional[List[dict]] = None


class SessionListResponse(BaseModel):
    """List of sessions."""

    items: List[SessionResponse]
    total: int


# --- Statistics Schemas ---


class AttackStats(BaseModel):
    """Attack statistics."""

    total_attacks: int
    attacks_today: int
    unique_ips: int
    top_countries: List[dict]
    attacks_by_service: dict
    attacks_by_threat_type: dict


class ServiceStatus(BaseModel):
    """Status of a honeypot service."""

    service: str
    running: bool
    host: str
    port: int
    connections: Optional[int] = 0


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(..., description="Overall health status")
    version: str = Field(..., description="Application version")
    timestamp: datetime
    services: List[ServiceStatus]
    database: str = Field(..., description="Database connection status")


# --- Query Parameters ---


class AttackQueryParams(BaseModel):
    """Query parameters for filtering attacks."""

    page: int = Field(1, ge=1, description="Page number")
    per_page: int = Field(20, ge=1, le=100, description="Items per page")
    service: Optional[str] = Field(None, description="Filter by service")
    threat_type: Optional[str] = Field(
        None, description="Filter by threat type"
    )
    ip: Optional[str] = Field(None, description="Filter by IP address")
    country: Optional[str] = Field(None, description="Filter by country code")
    start_date: Optional[datetime] = Field(
        None, description="Filter by start date"
    )
    end_date: Optional[datetime] = Field(
        None, description="Filter by end date"
    )
