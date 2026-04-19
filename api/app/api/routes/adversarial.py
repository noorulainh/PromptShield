from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.api import AdversarialRunRequest, AdversarialRunResponse
from app.services.adversarial import run_adversarial_suite
from app.services.settings_store import get_json_setting

router = APIRouter()


@router.post("/run", response_model=AdversarialRunResponse)
def run_suite(req: AdversarialRunRequest, db: Session = Depends(get_db)) -> dict:
    return run_adversarial_suite(db, req.mode)


@router.get("/latest")
def latest_suite(db: Session = Depends(get_db)) -> dict:
    return get_json_setting(
        db,
        "latest_adversarial",
        {
            "run_id": None,
            "mode": "ml_based",
            "leakage_rate": 0.0,
            "total_cases": 0,
            "passed_cases": 0,
            "average_latency_ms": 0.0,
            "results": [],
        },
    )
