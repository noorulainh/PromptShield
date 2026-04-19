from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import get_settings
from app.core.rate_limit import RateLimitMiddleware
from app.db.base import Base
from app.db.migrations import ensure_event_metadata_columns
from app.db.session import SessionLocal, engine
from app.services.adversarial import run_adversarial_suite
from app.services.evaluation import run_evaluation_suite
from app.services.seed import seed_default_settings
from app.services.settings_store import get_json_setting

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_event_metadata_columns(engine)
    with SessionLocal() as db:
        seed_default_settings(db)
        latest_eval = get_json_setting(db, "latest_evaluation", {})
        if not latest_eval or not latest_eval.get("mode_comparison"):
            run_evaluation_suite(db)

        latest_adv = get_json_setting(db, "latest_adversarial", {})
        if not latest_adv or int(latest_adv.get("total_cases", 0)) == 0:
            run_adversarial_suite(db, mode="ml_based")
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="PromptShield: Real-Time GenAI Privacy Guard",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)

app.include_router(api_router, prefix=settings.API_PREFIX)


@app.get("/")
def root() -> dict:
    return {
        "name": "PromptShield API",
        "status": "running",
        "docs": "/docs",
        "health": f"{settings.API_PREFIX}/health",
    }
