"""Demo attack-scenario endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.demo.schemas import DemoAttackScenarioResponse
from app.demo.service import DemoOrchestrator

router = APIRouter(prefix="/demo", tags=["demo"])


@router.post("/attack-scenario", response_model=DemoAttackScenarioResponse)
async def run_attack_scenario(db: Session = Depends(get_db)):
    """Execute the full one-click demo attack scenario.

    Ingests a realistic multi-stage attack, runs detection, correlation,
    AI investigation, recommendations, and report generation. Returns
    actual metrics from every pipeline stage.
    """
    return DemoOrchestrator().run(db)
