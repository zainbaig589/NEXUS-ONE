from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.schemas import EventCreate, EventResponse
from app.services import EventService, DetectionService

router = APIRouter(prefix="/events", tags=["events"])


@router.post("/", response_model=EventResponse, status_code=201)
async def create_event(event: EventCreate, db: Session = Depends(get_db)):
    db_event = EventService.create_event(db, event)
    # Run detection engine on the new event
    DetectionService.process_event(db, db_event)
    db.refresh(db_event)
    return db_event


@router.get("/", response_model=List[EventResponse])
async def list_events(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return EventService.get_events(db, skip=skip, limit=limit)
