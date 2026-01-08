from fastapi import APIRouter, Depends
from sqlmodel import Session, select, func
from backend.storage.db import get_session
from backend.models.sql import AccessLog, Decision



@router.get("/stats")
async def get_stats(session: Session = Depends(get_session)):
    # Total requests
    total_reqs = session.exec(select(func.count(AccessLog.id))).one()
    # Total threats (blocks/challenges)
    threats = session.exec(select(func.count(Decision.id)).where(Decision.action.in_(["block", "challenge"]))).one()
    
    return {
        "total_requests": total_reqs,
        "threats_blocked": threats,
        "risk_level": "High" if threats > 10 else "Low" # dynamic
    }

@router.get("/live-traffic")
async def get_live_traffic(limit: int = 20, session: Session = Depends(get_session)):
    # Get recent logs with their decisions
    statement = select(AccessLog, Decision).join(Decision).order_by(AccessLog.timestamp.desc()).limit(limit)
    results = session.exec(statement).all()
    
    traffic = []
    for log, dec in results:
        traffic.append({
            "id": log.id,
            "ip": log.ip,
            "method": log.method,
            "path": log.endpoint,
            "status": log.status_code,
            "risk_score": 90 if dec.action == "block" else 10, # Mock mapping
            "action": dec.action,
            "timestamp": log.timestamp
        })
        @router.get("/live-traffic")
async def get_live_traffic(limit: int = 20, session: Session = Depends(get_session)):
    # Get recent logs with their decisions
    statement = select(AccessLog, Decision).join(Decision).order_by(AccessLog.timestamp.desc()).limit(limit)
    results = session.exec(statement).all()
    
    traffic = []
    for log, dec in results:
        traffic.append({
            "id": log.id,
            "ip": log.ip,
            "method": log.method,
            "path": log.endpoint,
            "status": log.status_code,
            "risk_score": 90 if dec.action == "block" else 10, # Mock mapping
            "action": dec.action,
            "timestamp": log.timestamp
        })
    return traffic


