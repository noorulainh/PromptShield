from functools import lru_cache
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "PromptShield API"
    API_PREFIX: str = "/api/v1"
    DEMO_MODE: bool = True

    DATABASE_URL: str = "sqlite:///./promptshield.db"

    APP_SECRET: str = "change-me-in-env"
    MAPPING_ENCRYPTION_KEY: str = ""
    ADMIN_PASSWORD: str = "promptshield-admin"

    SESSION_COOKIE_NAME: str = "ps_admin"
    CSRF_COOKIE_NAME: str = "ps_csrf"

    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    RATE_LIMIT_WINDOW_SECONDS: int = 60
    RATE_LIMIT_MAX_REQUESTS: int = 120

    MAX_TEXT_LENGTH: int = 8000
    DEFAULT_MODE: str = "ml_based"
    ML_ENABLE_TRANSFORMER: bool = True
    ML_CLASSIFIER_TASK: str = "text-classification"
    ML_CLASSIFIER_MODEL: str = "../models/security_classifier_v3"
    ML_CONFIDENCE_THRESHOLD: float = 0.35
    ML_INJECTION_BLOCK_THRESHOLD: float = 0.62
    ML_MAX_CLASSIFICATION_CHARS: int = 2000
    PERSON_NER_MODEL: str = "Davlan/distilbert-base-multilingual-cased-ner-hrl"
    PERSON_NER_FALLBACK_MODEL: str = "dslim/bert-base-NER"
    PERSON_NER_MIN_SCORE: float = 0.65

    LLM_PROVIDER: str = "gemini"
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-flash-latest"
    LLM_TIMEOUT_SECONDS: float = 20.0

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: Any) -> list[str]:
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            parts = [item.strip() for item in value.split(",") if item.strip()]
            return parts or ["http://localhost:3000"]
        return ["http://localhost:3000"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
