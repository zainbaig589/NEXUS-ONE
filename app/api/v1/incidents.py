from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from typing import List, Optional

from app.ai.errors import (
    AIEvidenceValidationError,
    AIContextTooLargeError,
    AIProviderError,
    AIProviderNotConfiguredError,
    AIProviderTimeoutError,
    AIResponseValidationError,
)
from app.ai.service import InvestigationService
from app.database import get_db
from app.models.incident import Incident
from app.reports.html import render_report_html
from app.reports.schemas import IncidentReport
from app.reports.service import ReportService
from app.response.service import ResponseService
from app.schemas import (
    IncidentResponse,
    AlertResponse,
    CorrelationRequest,
    CorrelationResponse,
    RiskResponse,
    TimelineResponse,
    IncidentSummaryResponse,
    InvestigationResponse,
    RecommendationsResponse,
)
from app.services import IncidentService, CorrelationService, RiskService, TimelineService

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.post("/correlate", response_model=CorrelationResponse)
async def run_correlation(
    request: CorrelationRequest = None,
    db: Session = Depends(get_db),
):
    """Run the correlation engine on uncorrelated alerts."""
    body = request or CorrelationRequest()
    result = CorrelationService.run_with_stats(
        db,
        alert_ids=body.alert_ids,
        threshold=body.threshold,
        time_window_minutes=body.time_window_minutes,
    )

    return CorrelationResponse(
        incidents_touched=len(result.incidents),
        incidents_created=len(result.created_incident_ids),
        incidents_updated=len(result.updated_incident_ids),
        incident_ids=[i.id for i in result.incidents],
    )


@router.get("/", response_model=List[IncidentResponse])
async def list_incidents(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    return query.order_by(Incident.updated_at.desc()).offset(skip).limit(limit).all()


@router.get("/{incident_id}/risk", response_model=RiskResponse)
async def get_incident_risk(incident_id: str, db: Session = Depends(get_db)):
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    result = RiskService.get_risk(db, incident_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return RiskResponse(**result)


@router.get("/{incident_id}/timeline", response_model=TimelineResponse)
async def get_incident_timeline(incident_id: str, db: Session = Depends(get_db)):
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    result = TimelineService.get_timeline(db, incident_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return TimelineResponse(**result)


@router.get("/{incident_id}/summary", response_model=IncidentSummaryResponse)
async def get_incident_summary(incident_id: str, db: Session = Depends(get_db)):
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    risk = RiskService.get_risk(db, incident_id)
    timeline = TimelineService.get_timeline(db, incident_id)

    return IncidentSummaryResponse(
        incident=IncidentResponse.model_validate(incident),
        risk=RiskResponse(**risk),
        timeline=TimelineResponse(**timeline),
        potential_attack_stages=incident.attack_stages or [],
        related_alert_ids=incident.alert_ids or [],
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/{incident_id}/alerts", response_model=List[AlertResponse])
async def get_incident_alerts(incident_id: str, db: Session = Depends(get_db)):
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return CorrelationService.get_incident_alerts(db, incident_id)


@router.patch("/{incident_id}/status", response_model=IncidentResponse)
async def update_incident_status(
    incident_id: str,
    status: str,
    db: Session = Depends(get_db),
):
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = status
    db.commit()
    db.refresh(incident)
    return incident


@router.post("/{incident_id}/investigate", response_model=InvestigationResponse)
async def investigate_incident(incident_id: str, db: Session = Depends(get_db)):
    """Run an AI-powered investigation for an incident.

    Builds an evidence-only context (alerts, timeline, deterministic risk),
    sends it to the configured LLM provider, validates the structured
    response, and persists it as the incident's latest investigation.
    """
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    try:
        record = InvestigationService.investigate(db, incident_id)
    except AIProviderNotConfiguredError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except AIProviderTimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc))
    except AIProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except AIResponseValidationError as exc:
        raise HTTPException(
            status_code=502,
            detail={"message": str(exc), "validation_errors": exc.details},
        )
    except AIEvidenceValidationError as exc:
        raise HTTPException(
            status_code=502,
            detail={"message": str(exc), "unsupported_evidence_ids": exc.unsupported_ids},
        )
    except AIContextTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc))

    if record is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return InvestigationResponse(incident_id=incident_id, **record)


@router.get("/{incident_id}/investigation", response_model=InvestigationResponse)
async def get_incident_investigation(incident_id: str, db: Session = Depends(get_db)):
    """Retrieve the most recent AI investigation for an incident."""
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    record = incident.ai_analysis
    if not record:
        raise HTTPException(
            status_code=404,
            detail="No investigation has been run for this incident yet",
        )
    return InvestigationResponse(incident_id=incident_id, **record)


@router.get("/{incident_id}/recommendations", response_model=RecommendationsResponse)
async def get_incident_recommendations(incident_id: str, db: Session = Depends(get_db)):
    """Generate deterministic, evidence-based response recommendations.

    Recommendations are advisory only: nothing is executed automatically and
    every recommendation requires explicit analyst approval. A snapshot is
    persisted on the incident for auditability.
    """
    result = ResponseService.get_recommendations(db, incident_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


@router.post("/{incident_id}/report", response_model=IncidentReport)
async def generate_incident_report(
    incident_id: str,
    format: str = Query("json", pattern="^(json|html)$"),
    db: Session = Depends(get_db),
):
    """Generate a structured incident report and persist it.

    The report separates observed evidence, analysis (deterministic scoring
    plus advisory AI narrative), and recommended actions. HTML output is
    available via ``?format=html``.
    """
    report = ReportService.generate_report(db, incident_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if format == "html":
        return HTMLResponse(render_report_html(report))
    return report


@router.get("/{incident_id}/report", response_model=IncidentReport)
async def get_incident_report(
    incident_id: str,
    format: str = Query("json", pattern="^(json|html)$"),
    db: Session = Depends(get_db),
):
    """Retrieve the most recently generated report for an incident."""
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    content = ReportService.get_report(db, incident_id)
    if content is None:
        raise HTTPException(
            status_code=404,
            detail="No report has been generated for this incident yet",
        )
    report = IncidentReport.model_validate(content)
    if format == "html":
        return HTMLResponse(render_report_html(report))
    return report
