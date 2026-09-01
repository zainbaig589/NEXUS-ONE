"""ML anomaly detection endpoints."""

from fastapi import APIRouter, HTTPException
from app.schemas import MLAnalyzeRequest, MLAnalyzeResponse, MLTrainResponse, MLStatusResponse
from app.services.ml_service import MLService

router = APIRouter(prefix="/ml", tags=["ml"])


@router.post("/train", response_model=MLTrainResponse)
def train_model():
    """Train the Isolation Forest model on the synthetic dataset."""
    try:
        result = MLService.train()
        return MLTrainResponse(**result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/analyze", response_model=MLAnalyzeResponse)
def analyze_event(request: MLAnalyzeRequest):
    """Analyze a single event for anomalous behaviour."""
    try:
        result = MLService.analyze(
            source=request.source,
            event_type=request.event_type,
            severity=request.severity,
            payload=request.payload,
            timestamp=request.timestamp,
        )
        return MLAnalyzeResponse(**result)
    except FileNotFoundError:
        raise HTTPException(
            status_code=400,
            detail="Model not trained yet. Call POST /ml/train first.",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/status", response_model=MLStatusResponse)
def model_status():
    """Return current model status and metadata."""
    return MLStatusResponse(**MLService.status())
