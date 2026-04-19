from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.api import DashboardMetrics, SessionMetrics
from app.services.evaluation import run_evaluation_suite
from app.services.metrics import get_dashboard_metrics, get_session_metrics
from app.services.settings_store import get_json_setting

router = APIRouter()


@router.get("/dashboard", response_model=DashboardMetrics)
def dashboard_metrics(db: Session = Depends(get_db)) -> dict:
    return get_dashboard_metrics(db)


@router.get("/session/{session_id}", response_model=SessionMetrics)
def session_metrics(session_id: str, db: Session = Depends(get_db)) -> dict:
    return get_session_metrics(db, session_id)


@router.post("/evaluation/run")
def run_evaluation(db: Session = Depends(get_db)) -> dict:
    return run_evaluation_suite(db)


@router.get("/evaluation/latest")
def latest_evaluation(db: Session = Depends(get_db)) -> dict:
    return get_json_setting(db, "latest_evaluation", {"mode_comparison": {}})
