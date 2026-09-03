from fastapi import APIRouter
from app.schemas import HealthResponse
from app.config import settings

router = APIRouter()


@router.get("/")
async def root():
    return {
        "app_name": settings.APP_NAME,
        "version": "0.1.0",
        "description": "AI-powered Security Operations Center platform",
        "docs_url": "/docs",
    }


@router.get("/health", response_model=HealthResponse)
async def health_check():
    ml_status = "not_loaded"
    ai_provider = "unconfigured"

    try:
        from app.services.ml_service import MLService
        status = MLService.status()
        ml_status = "loaded" if status.get("model_loaded") else "not_loaded"
    except Exception:
        ml_status = "error"

    try:
        from app.ai.providers import get_provider
        provider = get_provider()
        ai_provider = provider.name
    except Exception:
        ai_provider = "error"

    return HealthResponse(
        status="healthy",
        app_name=settings.APP_NAME,
        version="0.1.0",
        environment=settings.APP_ENV,
        database="connected",
        ml_model=ml_status,
        ai_provider=ai_provider,
    )
