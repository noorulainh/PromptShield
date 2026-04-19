import math
import re
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from app.core.config import get_settings
from app.services.normalization import canonicalize_sensitive, normalize_for_detection

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


logger = logging.getLogger(__name__)


ModeType = Literal["detect_only", "redact", "pseudonymize", "combined"]


@dataclass
class Detection:
    entity_type: str
    start: int
    end: int
    matched_text: str
    confidence: float
    strategy: str
    placeholder: str | None = None


@dataclass
class OutputGuardResult:
    sanitized_text: str
    blocked: bool
    risk_score: float
    detections: list[Detection]
    reasons: list[str]


FLAGS = re.IGNORECASE | re.UNICODE
DIGIT = r"[0-9]"
PERSON_TOKEN = r"[a-z][a-z'\-]{1,30}"
PERSON_SECOND_TOKEN = r"(?!and\b|or\b|with\b|for\b|to\b|from\b|in\b|on\b|at\b|of\b|aur\b|ya\b)[a-z][a-z'\-]{1,30}"
ACCOUNT_DIGIT_TOKEN = rf"{DIGIT}(?:[\s\-\._:/,()]*{DIGIT}){{7,23}}"
PLACEHOLDER_TOKEN_RE = re.compile(r"\[(?:[A-Z_]+_\d+|[A-Z_]+_REDACTED)\]")

EMAIL_RE = re.compile(r"\b[a-z0-9._%+\-]+\s*(?:@|\[at\])\s*[a-z0-9.\-]+\s*(?:\.|\[dot\])\s*[a-z0-9]{2,}\b", FLAGS)
PHONE_PK_RE = re.compile(rf"(?:\+?\s*92|0)\s*[-() .:/]*3\s*(?:[-() .:/]*{DIGIT}){{9}}", FLAGS)
PHONE_CONTEXT_RE = re.compile(
    rf"(?:phone|mobile|cell|contact|number|num|no\.?|raabta|فون|نمبر)\s*(?:is|:|=|ka|کے|کا)?\s*[:\-]?\s*((?:{DIGIT}[\s\-\._:/,()]*){{8,14}})",
    FLAGS,
)
CNIC_RE = re.compile(rf"\b{DIGIT}{{5}}\s*[- ]?\s*{DIGIT}{{7}}\s*[- ]?\s*{DIGIT}\b", FLAGS)
CNIC_CONTEXT_RE = re.compile(
    rf"(?:cnic|شناختی(?:\s*کارڈ)?)(?:\s*(?:number|no\.?|نمبر))?\s*[:\-]?\s*((?:{DIGIT}[\s\-\._:/,()]*){{13}})",
    FLAGS,
)
IBAN_RE = re.compile(r"\bPK\s*\d{2}(?:\s*[A-Z0-9]{4}){5}\b", FLAGS)
ACCOUNT_CONTEXT_RE = re.compile(
    rf"(?:account(?:\s*number)?|acct|iban|bank\s*account|mera\s*account\s*number|khata\s*number|hisaab\s*number|اکاؤنٹ\s*نمبر|میرا\s*اکاؤنٹ\s*نمبر|حساب\s*نمبر)\s*[:\-]?\s*((?:PK\s*\d{{2}}(?:\s*[A-Z0-9]{{4}}){{5}}|{ACCOUNT_DIGIT_TOKEN}|[A-Z]{{2,6}}\d{{6,20}}))",
    FLAGS,
)
PASSPORT_RE = re.compile(r"\b[A-Z]{1,2}\d{7}\b", FLAGS)
NTN_RE = re.compile(rf"\b{DIGIT}{{7}}\s*[- ]?\s*{DIGIT}\b", FLAGS)
DOB_RE = re.compile(
    rf"(?:dob|date\s*of\s*birth|birth\s*date|paidaish|تاریخ\s*پیدائش)\s*[:\-]?\s*({DIGIT}{{1,2}}[/-]{DIGIT}{{1,2}}[/-]{DIGIT}{{2,4}})",
    FLAGS,
)
ADDRESS_RE = re.compile(
    r"\b(?:address|addr|ghar|pata|پتہ|street|road|sector|block)\b\s*[:\-]?\s*([\w\-#,./\s]{8,90})",
    FLAGS,
)
ORG_EN_RE = re.compile(r"\b([A-Za-z][A-Za-z& .\-]{2,60}(?:Bank|University|Hospital|Institute|Ltd|Corp|Foundation))\b", FLAGS)
ORG_URDU_RE = re.compile(r"\b(?:ادارہ|بینک|یونیورسٹی|کمپنی)\s+([\u0600-\u06FF\s]{2,40})", re.UNICODE)

PERSON_CONTEXT_EN_RE = re.compile(
    rf"\b(?:my\s*name\s*is|name\s*is|this\s*is|i\s*am|i['’]?m)\s+({PERSON_TOKEN}(?:\s+{PERSON_SECOND_TOKEN})?)",
    FLAGS,
)
PERSON_CONTEXT_ROMAN_RE = re.compile(
    rf"\b(?:mera\s*naam|naam)\s+({PERSON_TOKEN}(?:\s+{PERSON_SECOND_TOKEN})?)(?:\s+hai)?",
    FLAGS,
)
PERSON_CONTEXT_URDU_RE = re.compile(
    r"(?:میرا\s*نام)\s*[:\-]?\s*([\u0600-\u06FF]{2,}(?:\s+[\u0600-\u06FF]{2,}){0,2})(?:\s+ہے)?",
    re.UNICODE,
)
PERSON_LABELED_EN_RE = re.compile(
    rf"\b(?:full\s*name|customer\s*name|applicant\s*name|user\s*name|name)\s*(?:is|:|=)?\s*({PERSON_TOKEN}(?:\s+{PERSON_SECOND_TOKEN})?)",
    FLAGS,
)
PERSON_LABELED_ROMAN_RE = re.compile(
    rf"\b(?:mera\s*naam|naam)\s*(?:hai|:|=)?\s*({PERSON_TOKEN}(?:\s+{PERSON_SECOND_TOKEN})?)",
    FLAGS,
)
PERSON_LABELED_URDU_RE = re.compile(
    r"(?:نام|میرا\s*نام)\s*[:\-]?\s*([\u0600-\u06FF]{2,}(?:\s+[\u0600-\u06FF]{2,}){0,2})(?:\s+ہے)?",
    re.UNICODE,
)
PERSON_SIGNATURE_RE = re.compile(
    rf"\b(?:regards|best\s*regards|thanks|thank\s*you),?\s+({PERSON_TOKEN}(?:\s+{PERSON_SECOND_TOKEN})?)\b",
    FLAGS,
)
PERSON_POSSESSIVE_RE = re.compile(r"\b([a-z][a-z\-]{1,30})['’]s\s+(?:phone|number|mobile|cnic|account)\b", FLAGS)
PERSON_POSSESSIVE_ATTRIBUTE_RE = re.compile(
    r"\b([a-z][a-z\-]{1,30})['’]s\s+(?:favourite|favorite|food|name|email|passport|address|dob)\b",
    FLAGS,
)
PERSON_BELONGS_TO_RE = re.compile(
    rf"\b(?:belongs\s+to|owned\s+by|registered\s+to)\s+({PERSON_TOKEN}(?:\s+{PERSON_SECOND_TOKEN})?)\b",
    FLAGS,
)
PERSON_REFERENCE_ROMAN_RE = re.compile(r"\b([a-z][a-z'\-]{1,30})\s+ka\s+(?:cnic|phone|number|account)\b", FLAGS)

PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+previous\s+instructions", FLAGS),
    re.compile(r"(?:ignore|forget)\s+(?:all\s+)?previous\s+in(?:s)?tructions?", FLAGS),
    re.compile(r"reveal\s+(?:the\s+)?(?:original|hidden|raw)\s+(?:data|value|text|number|id)", FLAGS),
    re.compile(r"show\s+raw\s+data", FLAGS),
    re.compile(r"bypass\s+(?:safety|privacy|guard)", FLAGS),
    re.compile(r"deanonymize|unmask|unredact", FLAGS),
    re.compile(r"pichl[ie]\s+tamam\s+masking\s+ignore", FLAGS),
    re.compile(r"اصل\s+ڈیٹا\s+بتاؤ", re.UNICODE),
    re.compile(r"چھپ[ای]\s+ہو[ئےا]\s+ڈیٹا\s+(?:دکھاؤ|بتاؤ)", re.UNICODE),
]

EXTRACTION_QUERY_RE = re.compile(
    r"(?:cnic|iban|account|phone|number|email|شناختی|اکاؤنٹ|فون|نمبر)\s*(?:kya\s*hai|batao|batain|dikh[ao]|show|reveal|extract|nikalo|بتاؤ|بتائیں|دکھاؤ)",
    FLAGS,
)
PLACEHOLDER_EXTRACTION_RE = re.compile(
    r"(?:tell\s*me|what\s*(?:is|was)|show|reveal|extract|unmask|decode)\s+"
    r"(?:the\s+)?(?:cnic|iban|account|phone|number|email|data|value)?\s*(?:number|no\.?|id)?\s*"
    r"(?:of|for|from)?\s*(?:\[)?(?:person|phone|email|national_id|financial|address|date_of_birth|organization)[_\-]?\d+(?:\])?",
    FLAGS,
)
DIGIT_SEQUENCE_RE = re.compile(r"(?:[0-9][\s\-\._:/,()]*){8,24}", re.UNICODE)

PHONE_CONTEXT_WORDS = ("phone", "mobile", "contact", "number", "num", "no", "raabta", "فون", "نمبر")
FINANCIAL_CONTEXT_WORDS = ("account", "iban", "bank", "khata", "hisaab", "اکاؤنٹ", "حساب", "بینک")
PERSON_STOPWORDS = {
    "my",
    "mera",
    "name",
    "this",
    "that",
    "these",
    "those",
    "phone",
    "number",
    "mobile",
    "email",
    "passport",
    "passports",
    "contacted",
    "again",
    "from",
    "account",
    "khata",
    "hisaab",
    "full",
    "customer",
    "applicant",
    "user",
    "mr",
    "mrs",
    "ms",
    "dr",
    "sir",
    "madam",
    "cnic",
    "iban",
    "is",
    "hai",
    "aur",
    "ka",
    "ki",
    "and",
    "or",
    "to",
    "for",
    "belongs",
    "favorite",
    "favourite",
    "applying",
    "data",
    "science",
    "kindly",
    "check",
    "unauthorized",
    "transfer",
    "belongs",
    "unsafe",
    "assistant",
    "draft",
    "assalam",
    "assal",
    "alaikum",
    "salam",
    "salaam",
    "walekum",
    "show",
    "raw",
    "recovered",
    "secret",
    "referenced",
    "input",
    "note",
    "kar",
    "lo",
    "jaldi",
    "karein",
    "tell",
    "me",
    "can",
    "you",
    "u",
    "please",
    "what",
    "where",
    "who",
    "when",
    "why",
    "how",
    "are",
    "was",
    "were",
    "here",
    "there",
    "doing",
    "working",
}
PERSON_POSSESSIVE_IGNORE = {
    "it",
    "that",
    "there",
    "what",
    "where",
    "who",
    "he",
    "she",
    "let",
    "here",
    "how",
}

_detector_settings = get_settings()

PERSON_NER_MODEL = _detector_settings.PERSON_NER_MODEL
PERSON_NER_FALLBACK_MODEL = _detector_settings.PERSON_NER_FALLBACK_MODEL
PERSON_NER_MIN_SCORE = _detector_settings.PERSON_NER_MIN_SCORE
PERSON_NER_ALLOWED_GROUPS = {"B-PER", "I-PER", "PER"}
CAPITALIZED_NAME_RE = re.compile(r"[A-Z][a-z'\-]{1,30}")


def _load_person_ner_pipeline():
    def _build_pipeline(model_name: str):
        from transformers import pipeline  # type: ignore

        return pipeline(
            "ner",
            model=model_name,
            aggregation_strategy="simple",
            model_kwargs={"use_safetensors": False},
        )

    try:
        return _build_pipeline(PERSON_NER_MODEL)
    except Exception as primary_exc:  # pragma: no cover - environment dependent
        logger.warning("Primary PERSON NER model unavailable (%s): %s", PERSON_NER_MODEL, primary_exc)

    if PERSON_NER_FALLBACK_MODEL and PERSON_NER_FALLBACK_MODEL != PERSON_NER_MODEL:
        try:
            return _build_pipeline(PERSON_NER_FALLBACK_MODEL)
        except Exception as fallback_exc:  # pragma: no cover - environment dependent
            logger.warning(
                "Fallback PERSON NER model unavailable (%s): %s",
                PERSON_NER_FALLBACK_MODEL,
                fallback_exc,
            )

    logger.warning("PERSON NER pipeline unavailable; using classifier/regex fallback only")
    return None


# Cached at module import time to avoid per-request pipeline initialization overhead.
PERSON_NER_PIPELINE = _load_person_ner_pipeline()


def _merge_person_ner_spans(candidates: list[tuple[int, int, float]]) -> list[tuple[int, int, float]]:
    if not candidates:
        return []

    merged: list[tuple[int, int, float]] = []
    for start, end, score in sorted(candidates, key=lambda item: (item[0], item[1])):
        if not merged:
            merged.append((start, end, score))
            continue

        last_start, last_end, last_score = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end), max(last_score, score))
            continue

        merged.append((start, end, score))

    return merged


def _expand_person_ner_span(text: str, start: int, end: int) -> tuple[int, int]:
    # First extend to full alphabetic token boundaries (handles partial subword spans like "Ars" from "Arshia").
    while start > 0 and text[start - 1].isalpha():
        start -= 1
    while end < len(text) and text[end].isalpha():
        end += 1

    candidate = text[start:end].strip()
    token_count = len(candidate.split())

    # If NER captures only one token (e.g. "Fatima"), include adjacent capitalized token when plausible.
    if token_count <= 1:
        prefix = text[:start]
        prev_match = re.search(r"([A-Za-z][A-Za-z'\-]{1,30})\s*$", prefix)
        if prev_match:
            prev_token = prev_match.group(1).lower()
            if prev_token not in PERSON_STOPWORDS and prev_token not in PERSON_EXACT_BLOCKLIST:
                if CAPITALIZED_NAME_RE.fullmatch(prev_match.group(1)):
                    start = prev_match.start(1)

        suffix = text[end:]
        next_match = re.match(r"^\s*([A-Za-z][A-Za-z'\-]{1,30})", suffix)
        if next_match:
            next_token = next_match.group(1).lower()
            if next_token not in PERSON_STOPWORDS and next_token not in PERSON_EXACT_BLOCKLIST:
                if CAPITALIZED_NAME_RE.fullmatch(next_match.group(1)):
                    end = end + next_match.end(1)

    return start, end
PERSON_EXACT_BLOCKLIST = {
    "is",
    "am",
    "are",
    "was",
    "were",
    "name",
    "my",
    "mera",
    "naam",
    "hai",
}
PSEUDONYMIZABLE_ENTITY_TYPES = {
    "PERSON",
    "PHONE",
    "EMAIL",
    "NATIONAL_ID",
    "FINANCIAL",
    "ADDRESS",
    "DATE_OF_BIRTH",
    "ORGANIZATION",
}

RISK_WEIGHTS = {
    "PERSON": 0.72,
    "PHONE": 0.9,
    "EMAIL": 0.86,
    "NATIONAL_ID": 1.0,
    "FINANCIAL": 1.0,
    "ADDRESS": 0.8,
    "DATE_OF_BIRTH": 0.78,
    "ORGANIZATION": 0.38,
    "OTHER_SENSITIVE": 0.98,
}


def normalize_text(text: str) -> str:
    normalized = normalize_for_detection(text)
    normalized = normalized.replace("\r", "\n").replace("\t", " ")
    return normalized


def _add_detection(
    detections: list[Detection],
    entity_type: str,
    start: int,
    end: int,
    text: str,
    confidence: float,
    strategy: str,
) -> None:
    if start < 0 or end <= start or end > len(text):
        return
    matched = text[start:end]
    if not matched.strip():
        return

    if entity_type == "PERSON":
        candidate = matched.strip().lower()
        if candidate in PERSON_EXACT_BLOCKLIST:
            return
        person_tokens = [token for token in re.findall(r"[a-z][a-z'\-]{1,30}", candidate)]
        if person_tokens and any(token in PERSON_STOPWORDS for token in person_tokens):
            return
        if person_tokens and len(person_tokens) == 1 and len(person_tokens[0]) <= 2:
            return

    detections.append(
        Detection(
            entity_type=entity_type,
            start=start,
            end=end,
            matched_text=matched,
            confidence=round(confidence, 3),
            strategy=strategy,
        )
    )


def _span(match: re.Match[str]) -> tuple[int, int]:
    if match.lastindex:
        return match.span(1)
    return match.span()


def _dedupe_overlaps(detections: list[Detection]) -> list[Detection]:
    if not detections:
        return []

    ordered = sorted(detections, key=lambda item: (item.start, -(item.end - item.start), -item.confidence))
    accepted: list[Detection] = []

    for candidate in ordered:
        overlap_index = -1
        for idx, current in enumerate(accepted):
            if not (candidate.end <= current.start or candidate.start >= current.end):
                overlap_index = idx
                break

        if overlap_index < 0:
            accepted.append(candidate)
            continue

        current = accepted[overlap_index]
        candidate_score = (candidate.confidence, candidate.end - candidate.start)
        current_score = (current.confidence, current.end - current.start)
        if candidate_score > current_score:
            accepted[overlap_index] = candidate

    unique: dict[tuple[int, int, str], Detection] = {}
    for detection in accepted:
        key = (detection.start, detection.end, detection.entity_type)
        if key not in unique or unique[key].confidence < detection.confidence:
            unique[key] = detection

    return sorted(unique.values(), key=lambda item: item.start)


def _collect_pattern_matches(text: str, detections: list[Detection]) -> None:
    for match in EMAIL_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "EMAIL", start, end, text, 0.99, "regex_email")

    for match in PHONE_PK_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "PHONE", start, end, text, 0.96, "regex_pk_phone")

    for match in PHONE_CONTEXT_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "PHONE", start, end, text, 0.89, "context_phone_multilingual")

    for match in CNIC_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "NATIONAL_ID", start, end, text, 0.99, "regex_cnic")

    for match in CNIC_CONTEXT_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "NATIONAL_ID", start, end, text, 0.95, "context_cnic_spaced")

    for match in IBAN_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "FINANCIAL", start, end, text, 0.98, "regex_pk_iban")

    for match in ACCOUNT_CONTEXT_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "FINANCIAL", start, end, text, 0.91, "context_financial_multilingual")

    for match in PASSPORT_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "NATIONAL_ID", start, end, text, 0.82, "regex_passport_like")

    for match in NTN_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "NATIONAL_ID", start, end, text, 0.79, "regex_ntn")

    for match in DOB_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "DATE_OF_BIRTH", start, end, text, 0.9, "context_dob")

    for match in ADDRESS_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "ADDRESS", start, end, text, 0.76, "context_address")

    for match in ORG_EN_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "ORGANIZATION", start, end, text, 0.69, "org_suffix_english")

    for match in ORG_URDU_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "ORGANIZATION", start, end, text, 0.66, "org_suffix_urdu")


def _collect_person_matches(text: str, detections: list[Detection]) -> None:
    occupied_spans: list[tuple[int, int]] = [(item.start, item.end) for item in detections]

    def has_overlap(start: int, end: int) -> bool:
        return any(not (end <= span_start or start >= span_end) for span_start, span_end in occupied_spans)

    def add_person_if_free(start: int, end: int, confidence: float, strategy: str) -> None:
        if has_overlap(start, end):
            return
        before_count = len(detections)
        _add_detection(detections, "PERSON", start, end, text, confidence, strategy)
        if len(detections) > before_count:
            occupied_spans.append((start, end))

    # Priority 1: BERT NER (trusted when score >= threshold).
    if PERSON_NER_PIPELINE is not None:
        try:
            ner_rows = PERSON_NER_PIPELINE(text)
        except Exception as exc:  # pragma: no cover - runtime integration path
            logger.warning("PERSON NER inference failed; using fallback detectors: %s", exc)
            ner_rows = []

        person_candidates: list[tuple[int, int, float]] = []
        if isinstance(ner_rows, list):
            for row in ner_rows:
                if not isinstance(row, dict):
                    continue
                score = float(row.get("score", 0.0))
                if score < PERSON_NER_MIN_SCORE:
                    continue

                # `entity_group` is typical with aggregation_strategy="simple"; keep entity fallback for compatibility.
                entity_group = str(row.get("entity_group") or row.get("entity") or "").upper()
                if entity_group not in PERSON_NER_ALLOWED_GROUPS:
                    continue

                start = int(row.get("start", -1))
                end = int(row.get("end", -1))
                if start < 0 or end <= start or end > len(text):
                    continue

                person_candidates.append((start, end, min(score, 0.995)))

        for start, end, score in _merge_person_ner_spans(person_candidates):
            expanded_start, expanded_end = _expand_person_ner_span(text, start, end)
            add_person_if_free(expanded_start, expanded_end, score, "bert_person_ner")

    # Priority 2: existing context/labeled classifier-style heuristics.
    for match in PERSON_CONTEXT_EN_RE.finditer(text):
        start, end = _span(match)
        add_person_if_free(start, end, 0.84, "context_person_english")

    for match in PERSON_CONTEXT_ROMAN_RE.finditer(text):
        start, end = _span(match)
        add_person_if_free(start, end, 0.82, "context_person_roman_urdu")

    for match in PERSON_CONTEXT_URDU_RE.finditer(text):
        start, end = _span(match)
        add_person_if_free(start, end, 0.86, "context_person_urdu")

    for match in PERSON_LABELED_EN_RE.finditer(text):
        start, end = _span(match)
        add_person_if_free(start, end, 0.84, "labeled_person_english")

    for match in PERSON_LABELED_ROMAN_RE.finditer(text):
        start, end = _span(match)
        add_person_if_free(start, end, 0.83, "labeled_person_roman_urdu")

    for match in PERSON_LABELED_URDU_RE.finditer(text):
        start, end = _span(match)
        add_person_if_free(start, end, 0.86, "labeled_person_urdu")

    for match in PERSON_SIGNATURE_RE.finditer(text):
        start, end = _span(match)
        add_person_if_free(start, end, 0.78, "signature_person_english")

    for match in PERSON_POSSESSIVE_RE.finditer(text):
        start, end = _span(match)
        add_person_if_free(start, end, 0.76, "person_possessive_context")

    for match in PERSON_POSSESSIVE_ATTRIBUTE_RE.finditer(text):
        start, end = _span(match)
        if text[start:end].lower() in PERSON_POSSESSIVE_IGNORE:
            continue
        add_person_if_free(start, end, 0.74, "person_possessive_attribute")

    for match in PERSON_BELONGS_TO_RE.finditer(text):
        start, end = _span(match)
        add_person_if_free(start, end, 0.78, "person_belongs_to_context")

    for match in PERSON_REFERENCE_ROMAN_RE.finditer(text):
        start, end = _span(match)
        add_person_if_free(start, end, 0.7, "person_reference_roman_urdu")

    # Priority 3: regex shape fallback.
    for match in re.finditer(r"\b([a-z][a-z'\-]{1,30}\s+[a-z][a-z'\-]{1,30})\b", text, FLAGS):
        start, end = _span(match)
        candidate = text[start:end].lower()
        tokens = [token for token in candidate.split() if token]
        if not tokens or any(token in PERSON_STOPWORDS for token in tokens):
            continue
        context = text[max(0, start - 24) : min(len(text), end + 24)].lower()
        if any(token in context for token in ("phone", "number", "cnic", "account", "contact", "ticket")):
            add_person_if_free(start, end, 0.62, "person_shape_context")


def _collect_prompt_injection(text: str, detections: list[Detection], strict: bool) -> None:
    for pattern in PROMPT_INJECTION_PATTERNS:
        for match in pattern.finditer(text):
            start, end = _span(match)
            _add_detection(detections, "OTHER_SENSITIVE", start, end, text, 0.9 if strict else 0.86, "prompt_injection_heuristic")

    for match in EXTRACTION_QUERY_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "OTHER_SENSITIVE", start, end, text, 0.87 if strict else 0.82, "extraction_attempt_heuristic")

    for match in PLACEHOLDER_EXTRACTION_RE.finditer(text):
        start, end = _span(match)
        _add_detection(detections, "OTHER_SENSITIVE", start, end, text, 0.94 if strict else 0.9, "placeholder_exfiltration_heuristic")


def _collect_digit_sequence_heuristics(text: str, detections: list[Detection], strict: bool) -> None:
    for match in DIGIT_SEQUENCE_RE.finditer(text):
        start, end = _span(match)
        raw_value = text[start:end]
        digits = re.sub(r"\D", "", raw_value)
        if len(digits) < 8 or len(digits) > 20:
            continue

        context = text[max(0, start - 28) : min(len(text), end + 28)].lower()
        has_phone_context = any(word in context for word in PHONE_CONTEXT_WORDS)
        has_financial_context = any(word in context for word in FINANCIAL_CONTEXT_WORDS)
        has_id_context = any(word in context for word in ("cnic", "شناختی", "id", "passport", "ntn"))

        if has_id_context and len(digits) == 13:
            _add_detection(detections, "NATIONAL_ID", start, end, text, 0.9, "heuristic_digit_sequence_id")
            continue

        if has_phone_context and len(digits) >= 8:
            _add_detection(detections, "PHONE", start, end, text, 0.86, "heuristic_digit_sequence_phone")
            continue

        if has_financial_context and len(digits) >= 8:
            _add_detection(detections, "FINANCIAL", start, end, text, 0.9, "heuristic_digit_sequence_financial")
            continue

        if len(digits) >= 10:
            if digits.startswith("03") and len(digits) in {10, 11, 12}:
                _add_detection(detections, "PHONE", start, end, text, 0.78 if strict else 0.72, "heuristic_long_phone")
            else:
                _add_detection(detections, "FINANCIAL", start, end, text, 0.76 if strict else 0.7, "heuristic_long_digit_financial")


def detect_sensitive_entities(text: str, *, strict: bool = False) -> list[Detection]:
    scan_text = normalize_text(text)
    detections: list[Detection] = []

    _collect_pattern_matches(scan_text, detections)
    _collect_person_matches(scan_text, detections)
    _collect_prompt_injection(scan_text, detections, strict=strict)
    _collect_digit_sequence_heuristics(scan_text, detections, strict=strict)

    if strict and "other_sensitive" not in {d.entity_type.lower() for d in detections}:
        # In strict mode, explicit credential-like hints are treated as sensitive even without exact matches.
        for pattern in [re.compile(r"\b(?:password|otp|secret|token|pin)\b", FLAGS), re.compile(r"\b(?:خفیہ|راز|پاس\s*ورڈ)\b", re.UNICODE)]:
            for match in pattern.finditer(scan_text):
                start, end = _span(match)
                _add_detection(detections, "OTHER_SENSITIVE", start, end, scan_text, 0.8, "strict_sensitive_keyword")

    return _dedupe_overlaps(detections)


def redact_entities(text: str, detections: list[Detection]) -> str:
    if not detections:
        return text
    sanitized = text
    for detection in sorted(detections, key=lambda item: item.start, reverse=True):
        replacement = f"[{detection.entity_type}_REDACTED]"
        sanitized = f"{sanitized[:detection.start]}{replacement}{sanitized[detection.end:]}"
    return sanitized


def pseudonymize_entities(
    db: "Session",
    text: str,
    detections: list[Detection],
    session_id: str,
) -> tuple[str, list[Detection]]:
    from app.services.pseudonymizer import pseudonymize_text

    eligible = [item for item in detections if item.entity_type in PSEUDONYMIZABLE_ENTITY_TYPES]
    return pseudonymize_text(db, text, eligible, session_id)


def output_guard(text: str, *, strict: bool = True) -> OutputGuardResult:
    detections = [
        item
        for item in detect_sensitive_entities(text, strict=strict)
        if not PLACEHOLDER_TOKEN_RE.fullmatch(item.matched_text.strip())
    ]
    if not detections:
        return OutputGuardResult(
            sanitized_text=text,
            blocked=False,
            risk_score=calculate_risk_score([]),
            detections=[],
            reasons=["No sensitive indicators found in model output."],
        )

    sanitized = redact_entities(text, detections)
    reasons = sorted({f"{item.entity_type} via {item.strategy}" for item in detections})
    return OutputGuardResult(
        sanitized_text=sanitized,
        blocked=True,
        risk_score=calculate_risk_score(detections),
        detections=detections,
        reasons=reasons,
    )


def apply_privacy_mode(
    db: "Session",
    text: str,
    mode: ModeType,
    session_id: str,
) -> tuple[str, list[Detection]]:
    detections = detect_sensitive_entities(text)
    if mode == "detect_only":
        return text, detections
    if mode == "redact":
        return redact_entities(text, detections), detections

    pseudo_text, pseudo_detections = pseudonymize_entities(db, text, detections, session_id)
    placeholder_map = {
        (item.start, item.end, item.entity_type): item.placeholder
        for item in pseudo_detections
        if item.placeholder
    }
    merged_detections: list[Detection] = []
    seen_keys: set[tuple[int, int, str]] = set()
    for item in detections:
        key = (item.start, item.end, item.entity_type)
        if key in placeholder_map:
            item.placeholder = placeholder_map[key]
        merged_detections.append(item)
        seen_keys.add(key)

    for item in pseudo_detections:
        key = (item.start, item.end, item.entity_type)
        if key in seen_keys:
            continue
        merged_detections.append(item)
        seen_keys.add(key)

    if mode == "pseudonymize":
        return pseudo_text, merged_detections

    strict_output = output_guard(pseudo_text, strict=True)
    return strict_output.sanitized_text, merged_detections


def calculate_risk_score(detections: list[Detection]) -> float:
    if not detections:
        return 0.02

    weighted_sum = 0.0
    for detection in detections:
        weighted_sum += RISK_WEIGHTS.get(detection.entity_type, 0.45) * detection.confidence

    if any(
        "prompt_injection" in detection.strategy or "extraction_attempt" in detection.strategy
        for detection in detections
    ):
        weighted_sum += 2.0

    score = 1.0 - math.exp(-weighted_sum / 3.8)
    return round(max(0.0, min(1.0, score)), 3)


def entity_fingerprint(entity_type: str, raw_value: str) -> str:
    return f"{entity_type}:{canonicalize_sensitive(raw_value)}"
