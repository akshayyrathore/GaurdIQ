from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select, func
from datetime import datetime, timedelta

from backend.storage.db import get_session
from backend.models.sql import AccessLog, Decision

router = APIRouter()

# ---------------------------------------------------------
# Stats Endpoint (Enhanced)
# ---------------------------------------------------------
@router.get("/stats")
async def get_stats(
    last_minutes: int = Query(60, description="Time window for stats"),
    session: Session = Depends(get_session),
):
    since_time = datetime.utcnow() - timedelta(minutes=last_minutes)

    # Total requests
    total_requests = session.exec(
        select(func.count(AccessLog.id))
        .where(AccessLog.timestamp >= since_time)
    ).one()

    # Decisions count by action
    decision_counts = session.exec(
        select(Decision.action, func.count(Decision.id))
        .where(Decision.timestamp >= since_time)
        .group_by(Decision.action)
    ).all()

    action_stats = {action: count for action, count in decision_counts}

    threats_blocked = (
        action_stats.get("block", 0) +
        action_stats.get("challenge", 0)
    )

    threat_percentage = (
        round((threats_blocked / total_requests) * 100, 2)
        if total_requests > 0 else 0
    )

    # Top risky IPs
    top_ips = session.exec(
        select(AccessLog.ip, func.count(Decision.id))
        .join(Decision)
        .where(Decision.action.in_(["block", "challenge"]))
        .group_by(AccessLog.ip)
        .order_by(func.count(Decision.id).desc())
        .limit(5)
    ).all()

    # Dynamic risk level
    if threat_percentage > 30:
        risk_level = "Critical"
    elif threat_percentage > 15:
        risk_level = "High"
    elif threat_percentage > 5:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "time_window_minutes": last_minutes,
        "total_requests": total_requests,
        "threats_blocked": threats_blocked,
        "threat_percentage": threat_percentage,
        "risk_level": risk_level,
        "actions_breakdown": action_stats,
        "top_risky_ips": [
            {"ip": ip, "threat_count": count} for ip, count in top_ips
        ],
    }


# ---------------------------------------------------------
# Live Traffic Endpoint (Enhanced)
# ---------------------------------------------------------
@router.get("/live-traffic")
async def get_live_traffic(
    limit: int = Query(20, le=100),
    offset: int = 0,
    action: str | None = None,
    ip: str | None = None,
    method: str | None = None,
    min_risk: int = 0,
    session: Session = Depends(get_session),
):
    """
    Returns latest access logs with filters and pagination
    """

    statement = (
        select(AccessLog, Decision)
        .join(Decision, Decision.access_log_id == AccessLog.id)
        .order_by(AccessLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )

    if action:
        statement = statement.where(Decision.action == action)

    if ip:
        statement = statement.where(AccessLog.ip == ip)

    if method:
        statement = statement.where(AccessLog.method == method)

    results = session.exec(statement).all()

    traffic = []
    for log, dec in results:
        # Risk scoring
        risk_score_map = {
            "block": 95,
            "challenge": 65,
            "allow": 10,
            "monitor": 30,
        }
        risk_score = risk_score_map.get(dec.action, 20)

        if risk_score < min_risk:
            continue

        traffic.append({
            "id": log.id,
            "ip": log.ip,
            "method": log.method,
            "path": log.endpoint,
            "status": log.status_code,
            "risk_score": risk_score,
            "action": dec.action,
            "timestamp": log.timestamp,
        })
     class AccessLog(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    ip: str = Field(index=True)
    method: str
    endpoint: str
    status_code: int
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)

    __table_args__ = (
        Index("idx_accesslog_ip_timestamp", "ip", "timestamp"),
    )

    return {
        "count": len(traffic),
        "limit": limit,
        "offset": offset,
        "data": traffic,
    }

