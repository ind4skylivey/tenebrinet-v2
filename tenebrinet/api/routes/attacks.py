# tenebrinet/api/routes/attacks.py
"""
Attack API endpoints.

Provides REST endpoints for querying and managing attack records.
"""
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from tenebrinet.api.schemas import (
    AttackListResponse,
    AttackResponse,
    AttackStats,
    CredentialListResponse,
    CredentialResponse,
    SessionListResponse,
    SessionResponse,
)
from tenebrinet.core.database import get_db_session
from tenebrinet.core.models import Attack, Credential, Session


router = APIRouter(prefix="/attacks", tags=["attacks"])


@router.get("", response_model=AttackListResponse)
async def list_attacks(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    service: Optional[str] = Query(None, description="Filter by service"),
    threat_type: Optional[str] = Query(
        None, description="Filter by threat type"
    ),
    ip: Optional[str] = Query(None, description="Filter by IP address"),
    country: Optional[str] = Query(None, description="Filter by country"),
    start_date: Optional[datetime] = Query(
        None, description="Filter from date"
    ),
    end_date: Optional[datetime] = Query(None, description="Filter to date"),
    db: AsyncSession = Depends(get_db_session),
) -> AttackListResponse:
    """
    List all attacks with optional filtering and pagination.

    Returns a paginated list of attack records.
    """
    # Build query
    query = select(Attack)

    # Apply filters
    if service:
        query = query.where(Attack.service == service)
    if threat_type:
        query = query.where(Attack.threat_type == threat_type)
    if ip:
        query = query.where(Attack.ip == ip)
    if country:
        query = query.where(Attack.country == country)
    if start_date:
        query = query.where(Attack.timestamp >= start_date)
    if end_date:
        query = query.where(Attack.timestamp <= end_date)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Apply pagination
    offset = (page - 1) * per_page
    query = query.order_by(Attack.timestamp.desc())
    query = query.offset(offset).limit(per_page)

    # Execute query
    result = await db.execute(query)
    attacks = result.scalars().all()

    # Calculate total pages
    pages = (total + per_page - 1) // per_page if total > 0 else 0

    return AttackListResponse(
        items=[AttackResponse.model_validate(a) for a in attacks],
        total=total,
        page=page,
        per_page=per_page,
        pages=pages,
    )


@router.get("/stats", response_model=AttackStats)
async def get_attack_stats(
    db: AsyncSession = Depends(get_db_session),
) -> AttackStats:
    """
    Get attack statistics.

    Returns aggregated statistics about attacks.
    """
    # Total attacks
    total_result = await db.execute(select(func.count(Attack.id)))
    total_attacks = total_result.scalar() or 0

    # Attacks today
    today_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    today_result = await db.execute(
        select(func.count(Attack.id)).where(Attack.timestamp >= today_start)
    )
    attacks_today = today_result.scalar() or 0

    # Unique IPs
    unique_ips_result = await db.execute(
        select(func.count(func.distinct(Attack.ip)))
    )
    unique_ips = unique_ips_result.scalar() or 0

    # Top countries
    top_countries_query = (
        select(Attack.country, func.count(Attack.id).label("count"))
        .where(Attack.country.isnot(None))
        .group_by(Attack.country)
        .order_by(func.count(Attack.id).desc())
        .limit(10)
    )
    top_countries_result = await db.execute(top_countries_query)
    top_countries = [
        {"country": row[0], "count": row[1]}
        for row in top_countries_result.all()
    ]

    # Attacks by service
    by_service_query = (
        select(Attack.service, func.count(Attack.id).label("count"))
        .group_by(Attack.service)
    )
    by_service_result = await db.execute(by_service_query)
    attacks_by_service = {
        row[0]: row[1] for row in by_service_result.all()
    }

    # Attacks by threat type
    by_threat_query = (
        select(Attack.threat_type, func.count(Attack.id).label("count"))
        .where(Attack.threat_type.isnot(None))
        .group_by(Attack.threat_type)
    )
    by_threat_result = await db.execute(by_threat_query)
    attacks_by_threat_type = {
        row[0]: row[1] for row in by_threat_result.all()
    }

    return AttackStats(
        total_attacks=total_attacks,
        attacks_today=attacks_today,
        unique_ips=unique_ips,
        top_countries=top_countries,
        attacks_by_service=attacks_by_service,
        attacks_by_threat_type=attacks_by_threat_type,
    )


@router.get("/{attack_id}", response_model=AttackResponse)
async def get_attack(
    attack_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> AttackResponse:
    """
    Get a specific attack by ID.

    Returns the attack record with the given ID.
    """
    attack = await db.get(Attack, attack_id)
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")

    return AttackResponse.model_validate(attack)


@router.get("/{attack_id}/credentials", response_model=CredentialListResponse)
async def get_attack_credentials(
    attack_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> CredentialListResponse:
    """
    Get credentials associated with an attack.

    Returns all credential attempts from a specific attack.
    """
    # Verify attack exists
    attack = await db.get(Attack, attack_id)
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")

    # Get credentials
    query = select(Credential).where(Credential.attack_id == attack_id)
    result = await db.execute(query)
    credentials = result.scalars().all()

    return CredentialListResponse(
        items=[CredentialResponse.model_validate(c) for c in credentials],
        total=len(credentials),
    )


@router.get("/{attack_id}/sessions", response_model=SessionListResponse)
async def get_attack_sessions(
    attack_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> SessionListResponse:
    """
    Get sessions associated with an attack.

    Returns all sessions (shell interactions) from a specific attack.
    """
    # Verify attack exists
    attack = await db.get(Attack, attack_id)
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")

    # Get sessions
    query = select(Session).where(Session.attack_id == attack_id)
    result = await db.execute(query)
    sessions = result.scalars().all()

    return SessionListResponse(
        items=[SessionResponse.model_validate(s) for s in sessions],
        total=len(sessions),
    )


@router.delete("/{attack_id}", status_code=204)
async def delete_attack(
    attack_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> None:
    """
    Delete an attack and its related records.

    Removes the attack, its credentials, and sessions.
    """
    attack = await db.get(Attack, attack_id)
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")

    await db.delete(attack)
    await db.commit()
