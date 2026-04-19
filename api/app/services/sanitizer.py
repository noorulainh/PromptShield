from difflib import SequenceMatcher

from app.services.detector import Detection, redact_entities


def redact_text(text: str, detections: list[Detection]) -> str:
    return redact_entities(text, detections)


def utility_score(original: str, sanitized: str) -> float:
    if not original:
        return 1.0
    return round(SequenceMatcher(None, original, sanitized).ratio(), 3)
