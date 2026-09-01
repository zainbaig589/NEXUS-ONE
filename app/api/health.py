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
    return HealthResponse(
        status="healthy",
        app_name=settings.APP_NAME,
        version="0.1.0",
        environment=settings.APP_ENV,
        database="connected",
    )
