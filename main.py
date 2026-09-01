from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.config import settings
from app.database import init_db
from app.api import router as api_router
from app.api.health import router as health_router


@asynccontextmanager
async def lifespan(application: FastAPI):
    init_db(seed=settings.SEED_RULES)
    yield


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.APP_NAME,
        description="AI-powered Security Operations Center",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(health_router)
    application.include_router(api_router, prefix=settings.API_V1_PREFIX)

    return application


app = create_app()
