from sqlalchemy import and_, delete, desc, func, or_, select
from sqlalchemy.orm import Session

from app.core.security import hash_text
from app.db.models import DetectionModel, EncryptedMappingModel, EventModel, SanitizedOutputModel, SessionModel
from app.services.detector import Detection
from app.services.normalization import canonicalize_sensitive, collapse_whitespace, masked_excerpt


def _build_event_filters(
    *,
    session_id: str | None = None,
    min_risk: float | None = None,
    event_type: str | None = None,
    query: str | None = None,
    predicted_label: str | None = None,
    language: str | None = None,
    final_action: str | None = None,
) -> list:
    filters = []
    if session_id:
        filters.append(EventModel.session_id == session_id)
    if min_risk is not None:
        filters.append(EventModel.risk_score >= min_risk)
    if event_type:
        filters.append(EventModel.event_type == event_type)
    if predicted_label:
        filters.append(EventModel.predicted_label == predicted_label)
    if language:
        filters.append(EventModel.language == language)
    if final_action:
        filters.append(EventModel.final_action == final_action)
    if query:
        like_query = f"%{query}%"
        filters.append(
            or_(
                EventModel.summary.ilike(like_query),
                EventModel.sanitized_text.ilike(like_query),
                EventModel.raw_input_masked.ilike(like_query),
            )
        )
    return filters


def record_event(
    db: Session,
    *,
    session_id: str,
    event_type: str,
    mode: str,
    original_text: str,
    sanitized_text: str,
    detections: list[Detection],
    risk_score: float,
    latency_ms: float,
    utility_score: float | None = None,
    leakage_detected: bool = False,
    summary: str | None = None,
    direction: str = "input",
    raw_input_masked: str | None = None,
    language: str | None = None,
    predicted_label: str | None = None,
    confidence_score: float | None = None,
    pii_detected: bool = False,
    final_action: str | None = None,
    decision_source: str | None = None,
    decision_reasoning: list[str] | None = None,
    model_name: str | None = None,
) -> EventModel:
    request_fingerprint = hash_text(canonicalize_sensitive(original_text)[:512], context="request")
    safe_summary = summary or collapse_whitespace(sanitized_text)[:220]

    event = EventModel(
        session_id=session_id,
        event_type=event_type,
        mode=mode,
        risk_score=risk_score,
        latency_ms=latency_ms,
        utility_score=utility_score,
        leakage_detected=leakage_detected,
        request_fingerprint=request_fingerprint,
        raw_input_masked=raw_input_masked,
        summary=safe_summary,
        sanitized_text=sanitized_text,
        language=language,
        predicted_label=predicted_label,
        confidence_score=confidence_score,
        pii_detected=pii_detected,
        final_action=final_action,
        decision_source=decision_source,
        decision_reasoning=("; ".join(decision_reasoning)[:1800] if decision_reasoning else None),
        model_name=model_name,
    )
    db.add(event)
    db.flush()

    for detection in detections:
        raw_text = original_text[detection.start : detection.end]
        normalized_hash = hash_text(canonicalize_sensitive(raw_text), context=f"det:{session_id}")
        row = DetectionModel(
            event_id=event.id,
            session_id=session_id,
            entity_type=detection.entity_type,
            start_idx=detection.start,
            end_idx=detection.end,
            confidence=detection.confidence,
            strategy=detection.strategy,
            normalized_hash=normalized_hash,
            placeholder=detection.placeholder,
            excerpt=masked_excerpt(raw_text),
        )
        db.add(row)

    sanitized_row = SanitizedOutputModel(
        session_id=session_id,
        direction=direction,
        original_hash=request_fingerprint,
        sanitized_text=sanitized_text,
    )
    db.add(sanitized_row)
    db.commit()
    db.refresh(event)
    return event


def get_audit_logs(
    db: Session,
    *,
    session_id: str | None = None,
    min_risk: float | None = None,
    event_type: str | None = None,
    query: str | None = None,
    predicted_label: str | None = None,
    language: str | None = None,
    final_action: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[int, list[EventModel]]:
    filters = _build_event_filters(
        session_id=session_id,
        min_risk=min_risk,
        event_type=event_type,
        query=query,
        predicted_label=predicted_label,
        language=language,
        final_action=final_action,
    )

    base_stmt = select(EventModel)
    if filters:
        base_stmt = base_stmt.where(and_(*filters))

    count_stmt = select(func.count()).select_from(EventModel)
    if filters:
        count_stmt = count_stmt.where(and_(*filters))

    total = db.scalar(count_stmt) or 0
    rows = db.scalars(base_stmt.order_by(desc(EventModel.created_at)).offset(offset).limit(limit)).all()
    return total, rows


def clear_audit_logs(db: Session) -> dict:
    deleted_detections = db.execute(delete(DetectionModel)).rowcount or 0
    deleted_events = db.execute(delete(EventModel)).rowcount or 0
    deleted_sanitized_outputs = db.execute(delete(SanitizedOutputModel)).rowcount or 0
    deleted_mappings = db.execute(delete(EncryptedMappingModel)).rowcount or 0
    deleted_sessions = db.execute(delete(SessionModel)).rowcount or 0
    db.commit()
    return {
        "deleted_events": int(deleted_events),
        "deleted_detections": int(deleted_detections),
        "deleted_sanitized_outputs": int(deleted_sanitized_outputs),
        "deleted_mappings": int(deleted_mappings),
        "deleted_sessions": int(deleted_sessions),
    }
