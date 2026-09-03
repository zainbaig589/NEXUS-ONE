from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

    APP_NAME: str = "Nexus One"
    APP_ENV: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"

    DATABASE_URL: str = "sqlite:///./nexus_one.db"
    SECRET_KEY: str = "dev-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    API_V1_PREFIX: str = "/api/v1"

    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    ML_MODEL_PATH: Optional[str] = None
    SEED_RULES: bool = False

    # AI investigation layer (LLM provider).
    # LLM_PROVIDER: None (auto: openai when key present, otherwise unconfigured),
    # "openai" (OpenAI-compatible chat completions), or "demo" (deterministic
    # offline mock used for local development and demos).
    LLM_PROVIDER: Optional[str] = None
    LLM_API_KEY: Optional[str] = None
    LLM_MODEL: str = "gpt-4o-mini"
    LLM_BASE_URL: str = "https://api.openai.com/v1"
    LLM_TIMEOUT_SECONDS: float = 60.0
    LLM_MAX_CONTEXT_CHARS: int = 100_000
    LLM_MAX_ALERTS_IN_CONTEXT: int = 50


settings = Settings()
