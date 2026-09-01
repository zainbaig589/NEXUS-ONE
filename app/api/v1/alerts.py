from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database import get_db
from app.schemas import AlertResponse
from app.services import AlertService
from app.models.alert import Alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/", response_model=List[AlertResponse])
async def list_alerts(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status_filter:
        query = query.filter(Alert.status == status_filter)
    query = query.order_by(Alert.created_at.desc())
    return query.offset(skip).limit(limit).all()


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str, db: Session = Depends(get_db)):
    alert = AlertService.get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}/status", response_model=AlertResponse)
async def update_alert_status(
    alert_id: str,
    status: str,
    db: Session = Depends(get_db),
):
    alert = AlertService.get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = status
    db.commit()
    db.refresh(alert)
    return alert
