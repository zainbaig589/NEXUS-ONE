from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List

from app.database import get_db
from app.services import DetectionService
from app.schemas import AlertResponse

router = APIRouter(prefix="/detection", tags=["detection"])


class ProcessResponse(BaseModel):
    processed_count: int
    alerts_created: int


@router.post("/process", response_model=ProcessResponse)
async def process_unprocessed_events(limit: int = 100, db: Session = Depends(get_db)):
    """Process all unprocessed events through the detection engine."""
    result = DetectionService.process_unprocessed_events_with_stats(db, limit=limit)
    return ProcessResponse(
        processed_count=result.processed_count,
        alerts_created=len(result.alerts),
    )
