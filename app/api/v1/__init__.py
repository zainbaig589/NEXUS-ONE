from fastapi import APIRouter
from app.api.v1 import events, rules, alerts, detection, incidents, ml

router = APIRouter()
router.include_router(events.router)
router.include_router(rules.router)
router.include_router(alerts.router)
router.include_router(detection.router)
router.include_router(incidents.router)
router.include_router(ml.router)
