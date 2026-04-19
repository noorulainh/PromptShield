from dataclasses import dataclass
from typing import Literal

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.services.detector import (
    Detection,
    apply_privacy_mode,
    calculate_risk_score,
    detect_sensitive_entities,
    redact_entities,
)
from app.services.language import detect_input_language
from app.services.ml_classifier import MLClassification, classify_user_input

ActionType = Literal["allow", "mask", "block"]
PredictionLabel = Literal["safe", "injection", "pii"]
ProcessingMode = Literal["ml_based", "heuristic_based"]

PII_ENTITY_TYPES = {
    "PERSON",
    "PHONE",
    "EMAIL",
    "NATIONAL_ID",
    "FINANCIAL",
    "ADDRESS",
    "DATE_OF_BIRTH",
    "ORGANIZATION",
}

SAFE_MASK_MODE = "combined"
BLOCKED_INPUT_TEXT = "[UNSAFE_INPUT_BLOCKED]"


@dataclass
class SecurityDecision:
    sanitized_text: str
    detections: list[Detection]
    predicted_label: PredictionLabel
    confidence: float
    language: str
    final_action: ActionType
    decision_source: str
    reasoning: list[str]
    classifier_source: str
    model_name: str
    pii_detected: bool
    blocked: bool
    risk_score: float
    raw_input_for_audit: str


def _has_injection_signal(detections: list[Detection]) -> bool:
    return any("prompt_injection" in item.strategy or "extraction_attempt" in item.strategy for item in detections)


def _has_pii_signal(detections: list[Detection]) -> bool:
    return any(item.entity_type in PII_ENTITY_TYPES for item in detections)


def _heuristic_label_from_detections(detections: list[Detection]) -> PredictionLabel:
    if _has_injection_signal(detections):
        return "injection"
    if _has_pii_signal(detections):
        return "pii"
    return "safe"


def _heuristic_confidence(label: PredictionLabel, detections: list[Detection]) -> float:
    if label == "safe":
        return 0.71

    risk = calculate_risk_score(detections)
    if label == "injection":
        return round(min(0.96, 0.6 + risk * 0.4), 3)
    return round(min(0.94, 0.58 + risk * 0.36), 3)


def _mask_raw_input_for_audit(text: str, detections: list[Detection]) -> str:
    pii_detections = [item for item in detections if item.entity_type in PII_ENTITY_TYPES]
    if not pii_detections:
        return text
    return redact_entities(text, pii_detections)


def resolve_processing_mode(mode: str) -> ProcessingMode:
    normalized = (mode or "").strip().lower()
    if normalized in {"heuristic_based", "detect_only"}:
        return "heuristic_based"
    if normalized in {"ml_based", "redact", "pseudonymize", "combined"}:
        return "ml_based"
    return "ml_based"


def _apply_masking_mode(db: Session, text: str, session_id: str) -> tuple[str, list[Detection]]:
    # Redaction output style is unified to combined masking for consistent privacy behavior.
    return apply_privacy_mode(db, text, SAFE_MASK_MODE, session_id)


def run_security_pipeline(
    db: Session,
    *,
    text: str,
    mode: str,
    session_id: str,
    language_hint: str | None = None,
) -> SecurityDecision:
    processing_mode = resolve_processing_mode(mode)
    settings = get_settings()
    language = detect_input_language(text, language_hint).language

    rule_detections = detect_sensitive_entities(text, strict=True)
    rule_label = _heuristic_label_from_detections(rule_detections)
    pii_detected = _has_pii_signal(rule_detections)
    has_injection_signal = _has_injection_signal(rule_detections)

    if processing_mode == "heuristic_based":
        heuristic_reasoning = [
            "mode=heuristic_based",
            f"rule_label={rule_label}",
        ]

        if rule_label == "injection":
            return SecurityDecision(
                sanitized_text=BLOCKED_INPUT_TEXT,
                detections=rule_detections,
                predicted_label="injection",
                confidence=_heuristic_confidence("injection", rule_detections),
                language=language,
                final_action="block",
                decision_source="heuristic_based",
                reasoning=heuristic_reasoning,
                classifier_source="heuristic_fallback",
                model_name="heuristic-security-v1",
                pii_detected=pii_detected,
                blocked=True,
                risk_score=max(calculate_risk_score(rule_detections), 0.9),
                raw_input_for_audit=_mask_raw_input_for_audit(text, rule_detections),
            )

        if rule_label == "pii":
            sanitized, masked_detections = _apply_masking_mode(db, text, session_id)
            return SecurityDecision(
                sanitized_text=sanitized,
                detections=masked_detections,
                predicted_label="pii",
                confidence=_heuristic_confidence("pii", rule_detections),
                language=language,
                final_action="mask",
                decision_source="heuristic_based",
                reasoning=heuristic_reasoning,
                classifier_source="heuristic_fallback",
                model_name="heuristic-security-v1",
                pii_detected=True,
                blocked=False,
                risk_score=calculate_risk_score(masked_detections),
                raw_input_for_audit=_mask_raw_input_for_audit(text, masked_detections),
            )

        return SecurityDecision(
            sanitized_text=text,
            detections=[],
            predicted_label="safe",
            confidence=_heuristic_confidence("safe", []),
            language=language,
            final_action="allow",
            decision_source="heuristic_based",
            reasoning=heuristic_reasoning,
            classifier_source="heuristic_fallback",
            model_name="heuristic-security-v1",
            pii_detected=False,
            blocked=False,
            risk_score=0.02,
            raw_input_for_audit=text,
        )

    ml_result = classify_user_input(text, language_hint)

    use_ml_decision = ml_result.source == "transformer" and ml_result.confidence >= settings.ML_CONFIDENCE_THRESHOLD
    guarded_label_override: PredictionLabel | None = None
    fallback_reason: str | None = None

    # Guard against low-confidence ML injection false positives when rules do not indicate injection.
    if (
        use_ml_decision
        and ml_result.label == "injection"
        and ml_result.confidence < settings.ML_INJECTION_BLOCK_THRESHOLD
        and not has_injection_signal
    ):
        guarded_label_override = rule_label

    if use_ml_decision:
        predicted_label = guarded_label_override or ml_result.label
        confidence = (
            max(ml_result.confidence, _heuristic_confidence(predicted_label, rule_detections))
            if guarded_label_override is not None
            else ml_result.confidence
        )
        final_action: ActionType = "allow"
        blocked = False
        detections: list[Detection] = []
        sanitized = text
        reasoning = list(ml_result.reasoning)

        if guarded_label_override is not None:
            reasoning.append(
                f"ml_injection_not_confirmed:{ml_result.confidence:.3f}<"
                f"{settings.ML_INJECTION_BLOCK_THRESHOLD:.3f}"
            )
            reasoning.append(f"guardrail_override_to_rule_label:{guarded_label_override}")

        if predicted_label == "injection":
            final_action = "block"
            blocked = True
            detections = rule_detections
            sanitized = BLOCKED_INPUT_TEXT
            reasoning.append("high_confidence_transformer_injection")
        elif predicted_label == "pii":
            final_action = "mask"
            sanitized, detections = _apply_masking_mode(db, text, session_id)
            reasoning.append("high_confidence_transformer_pii")
        else:
            # Keep a safety net for missed PII/injection when model predicts safe.
            if rule_label == "injection":
                final_action = "block"
                blocked = True
                detections = rule_detections
                sanitized = BLOCKED_INPUT_TEXT
                reasoning.append("heuristic_override_for_injection")
            elif rule_label == "pii":
                final_action = "mask"
                sanitized, detections = _apply_masking_mode(db, text, session_id)
                reasoning.append("heuristic_override_for_detected_pii")

        risk_score = max(calculate_risk_score(detections), 0.92) if blocked else calculate_risk_score(detections)
        return SecurityDecision(
            sanitized_text=sanitized,
            detections=detections,
            predicted_label=predicted_label,
            confidence=confidence,
            language=ml_result.language,
            final_action=final_action,
            decision_source="ml_based",
            reasoning=reasoning,
            classifier_source=ml_result.source,
            model_name=ml_result.model_name,
            pii_detected=pii_detected,
            blocked=blocked,
            risk_score=risk_score,
            raw_input_for_audit=_mask_raw_input_for_audit(text, detections or rule_detections),
        )

    fallback_label = rule_label
    fallback_confidence = _heuristic_confidence(fallback_label, rule_detections)
    if fallback_reason is None:
        if ml_result.source != "transformer":
            fallback_reason = f"ml_source_not_transformer:{ml_result.source}"
        elif ml_result.confidence < settings.ML_CONFIDENCE_THRESHOLD:
            fallback_reason = (
                f"ml_confidence_below_threshold:{ml_result.confidence:.3f}<"
                f"{settings.ML_CONFIDENCE_THRESHOLD:.3f}"
            )
        else:
            fallback_reason = "ml_policy_override"

    fallback_reasoning = [
        fallback_reason,
        *ml_result.reasoning[:2],
        f"rule_label={rule_label}",
    ]

    if fallback_label == "injection":
        return SecurityDecision(
            sanitized_text=BLOCKED_INPUT_TEXT,
            detections=rule_detections,
            predicted_label="injection",
            confidence=fallback_confidence,
            language=ml_result.language,
            final_action="block",
            decision_source="heuristic_based",
            reasoning=fallback_reasoning,
            classifier_source=ml_result.source,
            model_name=ml_result.model_name,
            pii_detected=pii_detected,
            blocked=True,
            risk_score=max(calculate_risk_score(rule_detections), 0.9),
            raw_input_for_audit=_mask_raw_input_for_audit(text, rule_detections),
        )

    if fallback_label == "pii":
        sanitized, masked_detections = _apply_masking_mode(db, text, session_id)
        return SecurityDecision(
            sanitized_text=sanitized,
            detections=masked_detections,
            predicted_label="pii",
            confidence=fallback_confidence,
            language=ml_result.language,
            final_action="mask",
            decision_source="heuristic_based",
            reasoning=fallback_reasoning,
            classifier_source=ml_result.source,
            model_name=ml_result.model_name,
            pii_detected=True,
            blocked=False,
            risk_score=calculate_risk_score(masked_detections),
            raw_input_for_audit=_mask_raw_input_for_audit(text, masked_detections),
        )

    return SecurityDecision(
        sanitized_text=text,
        detections=[],
        predicted_label="safe",
        confidence=fallback_confidence,
        language=ml_result.language,
        final_action="allow",
        decision_source="heuristic_based",
        reasoning=fallback_reasoning,
        classifier_source=ml_result.source,
        model_name=ml_result.model_name,
        pii_detected=False,
        blocked=False,
        risk_score=0.02,
        raw_input_for_audit=text,
    )
