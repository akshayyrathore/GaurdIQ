from fastapi import APIRouter, Depends
from sqlmodel import Session, select, func
from backend.storage.db import get_session
from backend.models.sql import AccessLog, Decision

router = APIRouter()

# ---------------------------------------------------------
# Stats Endpoint
# ---------------------------------------------------------
@router.get("/stats")
async def get_stats(session: Session = Depends(get_session)):
    # Total requests
    total_requests = session.exec(
        select(func.count(AccessLog.id))
    ).one()

    # Total threats (block + challenge)
    threats_blocked = session.exec(
        select(func.count(Decision.id))
        .where(Decision.action.in_(["block", "challenge"]))
    ).one()

    # Simple dynamic risk level
    if threats_blocked > 50:
        risk_level = "High"
    elif threats_blocked > 10:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "total_requests": total_requests,
        "threats_blocked": threats_blocked,
        "risk_level": risk_level,
    }


# ---------------------------------------------------------
# Live Traffic Endpoint
# ---------------------------------------------------------
@router.get("/live-traffic")
async def get_live_traffic(
    limit: int = 20,
    session: Session = Depends(get_session),
):
    """
    Returns latest access logs with decisions
    """
    statement = (
        select(AccessLog, Decision)
        .join(Decision, Decision.access_log_id == AccessLog.id)
        .order_by(AccessLog.timestamp.desc())
        .limit(limit)
    )

    results = session.exec(statement).all()

    traffic = []
    for log, dec in results:
        # Simple risk mapping
        if dec.action == "block":
            risk_score = 95
        elif dec.action == "challenge":
            risk_score = 60
        else:
            risk_score = 10

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

    return traffic

