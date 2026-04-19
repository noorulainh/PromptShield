import re
from dataclasses import dataclass

from app.services.normalization import contains_roman_urdu, normalize_for_detection

URDU_SCRIPT_RE = re.compile(r"[\u0600-\u06FF]")
LATIN_SCRIPT_RE = re.compile(r"[A-Za-z]")


@dataclass(frozen=True)
class LanguageDetection:
    language: str
    confidence: float
    reasoning: str


def detect_input_language(text: str, language_hint: str | None = None) -> LanguageDetection:
    hinted = (language_hint or "").strip().lower()
    hint_map = {
        "en": "english",
        "eng": "english",
        "english": "english",
        "roman_urdu": "roman_urdu",
        "roman-urdu": "roman_urdu",
        "roman urdu": "roman_urdu",
        "ur": "urdu_script",
        "urdu": "urdu_script",
        "urdu_script": "urdu_script",
        "urdu script": "urdu_script",
        "mixed": "mixed",
    }
    if hinted in hint_map:
        mapped = hint_map[hinted]
        return LanguageDetection(language=mapped, confidence=0.99, reasoning="language_hint")

    normalized = normalize_for_detection(text)
    has_urdu = bool(URDU_SCRIPT_RE.search(normalized))
    has_latin = bool(LATIN_SCRIPT_RE.search(normalized))

    if has_urdu and has_latin:
        return LanguageDetection(language="mixed", confidence=0.93, reasoning="mixed_script_detection")
    if has_urdu:
        return LanguageDetection(language="urdu_script", confidence=0.95, reasoning="urdu_script_detection")
    if contains_roman_urdu(normalized):
        return LanguageDetection(language="roman_urdu", confidence=0.81, reasoning="roman_urdu_keyword_detection")
    return LanguageDetection(language="english", confidence=0.74, reasoning="latin_default_detection")
