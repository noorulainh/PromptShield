import csv
import io

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.api import AuditLogResponse
from app.services.audit import clear_audit_logs, get_audit_logs

router = APIRouter()


@router.get("/logs", response_model=AuditLogResponse)
def audit_logs(
    session_id: str | None = None,
    min_risk: float | None = Query(default=None, ge=0, le=1),
    event_type: str | None = None,
    q: str | None = None,
    predicted_label: str | None = None,
    language: str | None = None,
    final_action: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    total, rows = get_audit_logs(
        db,
        session_id=session_id,
        min_risk=min_risk,
        event_type=event_type,
        query=q,
        predicted_label=predicted_label,
        language=language,
        final_action=final_action,
        limit=limit,
        offset=offset,
    )
    return {
        "total": total,
        "items": [
            {
                "id": row.id,
                "session_id": row.session_id,
                "event_type": row.event_type,
                "mode": row.mode,
                "raw_input": row.raw_input_masked,
                "language": row.language,
                "predicted_label": row.predicted_label,
                "confidence_score": row.confidence_score,
                "pii_detected": bool(row.pii_detected),
                "final_action": row.final_action,
                "decision_source": row.decision_source,
                "risk_score": row.risk_score,
                "latency_ms": row.latency_ms,
                "leakage_detected": row.leakage_detected,
                "summary": row.summary,
                "sanitized_text": row.sanitized_text,
                "created_at": row.created_at,
            }
            for row in rows
        ],
    }


@router.get("/export.csv")
def export_audit_logs(
    session_id: str | None = None,
    min_risk: float | None = Query(default=None, ge=0, le=1),
    event_type: str | None = None,
    q: str | None = None,
    predicted_label: str | None = None,
    language: str | None = None,
    final_action: str | None = None,
    db: Session = Depends(get_db),
):
    _, rows = get_audit_logs(
        db,
        session_id=session_id,
        min_risk=min_risk,
        event_type=event_type,
        query=q,
        predicted_label=predicted_label,
        language=language,
        final_action=final_action,
        limit=5000,
        offset=0,
    )

    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(
        [
            "id",
            "session_id",
            "event_type",
            "mode",
            "raw_input",
            "language",
            "predicted_label",
            "confidence_score",
            "pii_detected",
            "final_action",
            "decision_source",
            "risk_score",
            "latency_ms",
            "leakage_detected",
            "summary",
            "created_at",
        ]
    )

    for row in rows:
        writer.writerow(
            [
                row.id,
                row.session_id,
                row.event_type,
                row.mode,
                row.raw_input_masked,
                row.language,
                row.predicted_label,
                row.confidence_score,
                row.pii_detected,
                row.final_action,
                row.decision_source,
                row.risk_score,
                row.latency_ms,
                row.leakage_detected,
                row.summary,
                row.created_at.isoformat(),
            ]
        )

    stream.seek(0)
    headers = {"Content-Disposition": "attachment; filename=promptshield_audit.csv"}
    return StreamingResponse(iter([stream.getvalue()]), media_type="text/csv", headers=headers)


@router.delete("/logs")
def clear_logs(db: Session = Depends(get_db)) -> dict:
    return clear_audit_logs(db)
