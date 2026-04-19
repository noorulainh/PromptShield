import time

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_client_hash, get_db
from app.schemas.api import OutputGuardRequest, ProcessRequest, ProcessResponse, TextRequest
from app.services.audit import record_event
from app.services.detector import (
    Detection,
    output_guard,
    redact_entities,
)
from app.services.language import detect_input_language
from app.services.mock_llm import generate_assistant_response
from app.services.pseudonymizer import ensure_session, generate_session_id
from app.services.security_pipeline import resolve_processing_mode, run_security_pipeline
from app.services.sanitizer import utility_score
from app.services.settings_store import get_app_settings

router = APIRouter()


def _serialize_detections(detections: list[Detection]) -> list[dict]:
    return [
        {
            "entity_type": item.entity_type,
            "start": item.start,
            "end": item.end,
            "matched_text": item.matched_text,
            "confidence": item.confidence,
            "strategy": item.strategy,
            "placeholder": item.placeholder,
        }
        for item in detections
    ]


def _process_payload(req: ProcessRequest, request: Request, db: Session) -> ProcessResponse:
    start = time.perf_counter()
    session_id = req.session_id or generate_session_id()
    processing_mode = resolve_processing_mode(req.mode)
    ensure_session(db, session_id, get_client_hash(request))

    decision = run_security_pipeline(
        db,
        text=req.text,
        mode=processing_mode,
        session_id=session_id,
        language_hint=req.language_hint,
    )
    latency_ms = (time.perf_counter() - start) * 1000
    util = utility_score(req.text, decision.sanitized_text)

    record_event(
        db,
        session_id=session_id,
        event_type="prompt_process",
        mode=processing_mode,
        original_text=req.text,
        sanitized_text=decision.sanitized_text,
        detections=decision.detections,
        risk_score=decision.risk_score,
        latency_ms=latency_ms,
        utility_score=util,
        summary=(
            f"{decision.final_action.upper()} via {decision.decision_source}; "
            f"label={decision.predicted_label}; confidence={decision.confidence:.2f}"
        ),
        raw_input_masked=decision.raw_input_for_audit,
        language=decision.language,
        predicted_label=decision.predicted_label,
        confidence_score=decision.confidence,
        pii_detected=decision.pii_detected,
        final_action=decision.final_action,
        decision_source=decision.decision_source,
        decision_reasoning=decision.reasoning,
        model_name=decision.model_name,
    )

    return ProcessResponse(
        session_id=session_id,
        mode=processing_mode,
        sanitized_text=decision.sanitized_text,
        detections=_serialize_detections(decision.detections),
        risk_score=decision.risk_score,
        utility_score=util,
        latency_ms=round(latency_ms, 2),
        predicted_label=decision.predicted_label,
        confidence_score=decision.confidence,
        language=decision.language,
        decision_source=decision.decision_source,
        final_action=decision.final_action,
        reasoning=decision.reasoning,
        pii_detected=decision.pii_detected,
        blocked=decision.blocked,
        message=(
            "Input blocked due to unsafe prompt injection risk."
            if decision.blocked
            else "Input masked for privacy-safe processing."
            if decision.final_action == "mask"
            else "Input allowed."
        ),
    )


@router.post("/process", response_model=ProcessResponse)
def process_text(req: ProcessRequest, request: Request, db: Session = Depends(get_db)) -> ProcessResponse:
    return _process_payload(req, request, db)


@router.post("/analyze", response_model=ProcessResponse)
def analyze_prompt(req: TextRequest, request: Request, db: Session = Depends(get_db)) -> ProcessResponse:
    payload = ProcessRequest(text=req.text, session_id=req.session_id, language_hint=req.language_hint, mode="heuristic_based")
    return _process_payload(payload, request, db)


@router.post("/redact", response_model=ProcessResponse)
def redact_prompt(req: TextRequest, request: Request, db: Session = Depends(get_db)) -> ProcessResponse:
    payload = ProcessRequest(text=req.text, session_id=req.session_id, language_hint=req.language_hint, mode="ml_based")
    return _process_payload(payload, request, db)


@router.post("/pseudonymize", response_model=ProcessResponse)
def pseudonymize_prompt(req: TextRequest, request: Request, db: Session = Depends(get_db)) -> ProcessResponse:
    payload = ProcessRequest(text=req.text, session_id=req.session_id, language_hint=req.language_hint, mode="ml_based")
    return _process_payload(payload, request, db)


@router.post("/output/analyze", response_model=ProcessResponse)
def analyze_model_output(req: OutputGuardRequest, request: Request, db: Session = Depends(get_db)) -> ProcessResponse:
    start = time.perf_counter()
    session_id = req.session_id or generate_session_id()
    ensure_session(db, session_id, get_client_hash(request))

    guarded = output_guard(req.text, strict=True)
    detections = guarded.detections
    language = detect_input_language(req.text, req.language_hint).language

    app_settings = get_app_settings(db)
    threshold = float(app_settings.get("risk_threshold", 0.6))
    output_risk = guarded.risk_score
    block_high_risk = bool(app_settings.get("block_high_risk_output", True))
    should_block = guarded.blocked and req.strict and block_high_risk and output_risk >= threshold
    safe_output = guarded.sanitized_text if guarded.blocked else req.text

    latency_ms = (time.perf_counter() - start) * 1000
    util = utility_score(req.text, safe_output)

    record_event(
        db,
        session_id=session_id,
        event_type="output_guard",
        mode="heuristic_based",
        original_text=req.text,
        sanitized_text=safe_output,
        detections=detections,
        risk_score=output_risk,
        latency_ms=latency_ms,
        utility_score=util,
        leakage_detected=guarded.blocked,
        summary=(
            f"Output guard flagged: {'; '.join(guarded.reasons[:2])}"
            if guarded.blocked
            else "Model output clean"
        ),
        direction="output",
        raw_input_masked=redact_entities(req.text, detections) if detections else req.text,
        language=language,
        predicted_label="pii" if guarded.blocked else "safe",
        confidence_score=max((item.confidence for item in detections), default=0.81),
        pii_detected=bool(detections),
        final_action="mask" if guarded.blocked else "allow",
        decision_source="output_guard",
        decision_reasoning=guarded.reasons,
        model_name="output_guard_heuristics",
    )

    return ProcessResponse(
        session_id=session_id,
        mode="heuristic_based",
        sanitized_text=safe_output,
        detections=_serialize_detections(detections),
        risk_score=round(output_risk, 3),
        utility_score=util,
        latency_ms=round(latency_ms, 2),
        predicted_label="pii" if guarded.blocked else "safe",
        confidence_score=round(max((item.confidence for item in detections), default=0.81), 3),
        language=language,
        decision_source="output_guard",
        final_action="mask" if guarded.blocked else "allow",
        reasoning=guarded.reasons,
        pii_detected=bool(detections),
        blocked=should_block,
        message=(
            f"Output leakage detected and sanitized: {'; '.join(guarded.reasons[:3])}"
            if guarded.blocked
            else "Output is safe."
        ),
    )


@router.post("/chat/simulate")
def simulate_chat(req: ProcessRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    start = time.perf_counter()
    session_id = req.session_id or generate_session_id()
    ensure_session(db, session_id, get_client_hash(request))
    mode = resolve_processing_mode(req.mode)

    decision = run_security_pipeline(
        db,
        text=req.text,
        mode=mode,
        session_id=session_id,
        language_hint=req.language_hint,
    )

    input_blocked = decision.blocked
    output_blocked = False
    output_risk = 0.02
    model_output = ""
    guarded_output = ""
    output_detections: list[Detection] = []
    output_reasons: list[str] = []

    if input_blocked:
        guarded_output = (
            "This message was blocked because PromptShield detected a likely prompt injection attempt. "
            "Please rephrase without bypass or data extraction instructions."
        )
    else:
        model_output = generate_assistant_response(decision.sanitized_text)
        guarded = output_guard(model_output, strict=True)
        guarded_output = guarded.sanitized_text
        output_blocked = guarded.blocked
        output_risk = guarded.risk_score
        output_detections = guarded.detections
        output_reasons = guarded.reasons

    latency_ms = (time.perf_counter() - start) * 1000

    record_event(
        db,
        session_id=session_id,
        event_type="conversation_turn",
        mode=mode,
        original_text=req.text,
        sanitized_text=decision.sanitized_text,
        detections=decision.detections,
        risk_score=decision.risk_score,
        latency_ms=latency_ms,
        utility_score=utility_score(req.text, decision.sanitized_text),
        summary=(
            f"chat_input:{decision.final_action}; label={decision.predicted_label}; conf={decision.confidence:.2f}"
        ),
        raw_input_masked=decision.raw_input_for_audit,
        language=decision.language,
        predicted_label=decision.predicted_label,
        confidence_score=decision.confidence,
        pii_detected=decision.pii_detected,
        final_action=decision.final_action,
        decision_source=decision.decision_source,
        decision_reasoning=decision.reasoning,
        model_name=decision.model_name,
    )

    if not input_blocked:
        record_event(
            db,
            session_id=session_id,
            event_type="conversation_output",
            mode=mode,
            original_text=model_output,
            sanitized_text=guarded_output,
            detections=output_detections,
            risk_score=output_risk,
            latency_ms=latency_ms,
            utility_score=utility_score(model_output, guarded_output),
            leakage_detected=output_blocked,
            summary=(
                f"Conversation output filtered: {'; '.join(output_reasons[:2])}"
                if output_blocked
                else "Conversation output clean"
            ),
            direction="output",
            raw_input_masked=redact_entities(model_output, output_detections) if output_detections else model_output,
            language=decision.language,
            predicted_label="pii" if output_blocked else "safe",
            confidence_score=max((item.confidence for item in output_detections), default=0.81),
            pii_detected=bool(output_detections),
            final_action="mask" if output_blocked else "allow",
            decision_source="output_guard",
            decision_reasoning=output_reasons,
            model_name="output_guard_heuristics",
        )

    warning = None
    if input_blocked:
        warning = "Unsafe prompt injection detected and blocked before model execution."
    elif output_blocked:
        warning = "Potential sensitive leakage detected in model output and masked."

    return {
        "session_id": session_id,
        "sanitized_prompt": decision.sanitized_text,
        "model_response": guarded_output,
        "blocked": input_blocked or output_blocked,
        "input_blocked": input_blocked,
        "output_blocked": output_blocked,
        "predicted_label": decision.predicted_label,
        "confidence_score": decision.confidence,
        "language": decision.language,
        "final_action": decision.final_action,
        "decision_source": decision.decision_source,
        "reasoning": decision.reasoning,
        "pii_detected": decision.pii_detected,
        "warning": warning,
        "latency_ms": round(latency_ms, 2),
    }


@router.post("/session/new")
def create_session(request: Request, db: Session = Depends(get_db)) -> dict:
    session_id = generate_session_id()
    ensure_session(db, session_id, get_client_hash(request))
    return {"session_id": session_id}
