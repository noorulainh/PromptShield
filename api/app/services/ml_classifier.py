import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from app.core.config import get_settings
from app.services.language import detect_input_language
from app.services.normalization import normalize_for_detection

ClassificationLabel = Literal["safe", "injection", "pii"]
ClassifierSource = Literal["transformer", "heuristic_fallback"]

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

INJECTION_HINT_RE = re.compile(
    r"ignore\s+previous\s+instructions|bypass\s+(?:safety|privacy|guard)|unmask|unredact|"
    r"reveal\s+(?:raw|hidden|original)|اصل\s+ڈیٹا\s+بتاؤ|چھپ[ای]\s+ہو[ئےا]\s+ڈیٹا",
    re.IGNORECASE | re.UNICODE,
)

OBFUSCATED_PII_HINT_RE = re.compile(
    r"(?:\[at\]|\[dot\]|[0-9][\s\-\._:/,()]*[0-9][\s\-\._:/,()]*[0-9][\s\-\._:/,()]*[0-9])",
    re.IGNORECASE | re.UNICODE,
)

LABEL_DESCRIPTIONS = {
    "safe": "safe user request",
    "injection": "prompt injection attempt",
    "pii": "pii exposure or extraction attempt",
}

logger = logging.getLogger(__name__)


def _map_label(raw_label: str) -> ClassificationLabel:
    label = raw_label.strip().lower()
    if label in {"safe", "label_0", "0"}:
        return "safe"
    if "inject" in label or label in {"label_1", "1"}:
        return "injection"
    if "pii" in label or "exposure" in label or "extract" in label or label in {"label_2", "2"}:
        return "pii"
    return "safe"


@dataclass(frozen=True)
class MLClassification:
    label: ClassificationLabel
    confidence: float
    language: str
    reasoning: list[str]
    scores: dict[str, float]
    source: ClassifierSource
    model_name: str


def _normalize_scores(scores: dict[str, float]) -> dict[str, float]:
    total = sum(max(value, 0.0) for value in scores.values())
    if total <= 0:
        return {"safe": 0.34, "injection": 0.33, "pii": 0.33}
    return {key: round(max(value, 0.0) / total, 4) for key, value in scores.items()}


@lru_cache(maxsize=1)
def _load_transformer_pipeline():
    settings = get_settings()
    if not settings.ML_ENABLE_TRANSFORMER:
        return None

    task = settings.ML_CLASSIFIER_TASK.strip().lower() or "zero-shot-classification"
    if task not in {"zero-shot-classification", "text-classification"}:
        logger.warning("Unsupported ML_CLASSIFIER_TASK '%s'; defaulting to zero-shot-classification", task)
        task = "zero-shot-classification"

    try:
        from transformers import pipeline  # type: ignore

        if task == "text-classification":
            return (
                pipeline(
                    "text-classification",
                    model=settings.ML_CLASSIFIER_MODEL,
                    device=-1,
                ),
                task,
            )

        return (
            pipeline(
                "zero-shot-classification",
                model=settings.ML_CLASSIFIER_MODEL,
                device=-1,
            ),
            task,
        )
    except Exception as exc:  # pragma: no cover - environment dependent
        logger.warning("Transformer classifier unavailable; falling back to heuristic scorer: %s", exc)
        return None


def _heuristic_classification(text: str, language: str) -> MLClassification:
    from app.services.detector import detect_sensitive_entities

    normalized = normalize_for_detection(text).lower()
    detections = detect_sensitive_entities(text, strict=True)

    injection_hits = sum(
        1
        for item in detections
        if "prompt_injection" in item.strategy or "extraction_attempt" in item.strategy
    )
    pii_hits = sum(1 for item in detections if item.entity_type in PII_ENTITY_TYPES)
    keyword_injection_hits = len(INJECTION_HINT_RE.findall(normalized))
    obfuscated_pii_hints = len(OBFUSCATED_PII_HINT_RE.findall(normalized))

    scores = {
        "safe": 0.28,
        "injection": 0.26,
        "pii": 0.26,
    }

    scores["injection"] += injection_hits * 0.34 + keyword_injection_hits * 0.16
    scores["pii"] += pii_hits * 0.24 + min(obfuscated_pii_hints, 6) * 0.06

    if pii_hits == 0 and injection_hits == 0 and keyword_injection_hits == 0:
        scores["safe"] += 0.6
    else:
        scores["safe"] += max(0.05, 0.2 - 0.08 * (pii_hits + injection_hits + keyword_injection_hits))

    normalized_scores = _normalize_scores(scores)
    sorted_scores = sorted(normalized_scores.items(), key=lambda item: item[1], reverse=True)
    label = sorted_scores[0][0]
    confidence = round(sorted_scores[0][1], 3)

    reasoning = [
        f"language={language}",
        f"pii_hits={pii_hits}, injection_hits={injection_hits}",
        f"obfuscation_hints={obfuscated_pii_hints}, keyword_injection_hits={keyword_injection_hits}",
        "transformer_unavailable_or_low_confidence",
    ]

    return MLClassification(
        label=label,
        confidence=confidence,
        language=language,
        reasoning=reasoning,
        scores=normalized_scores,
        source="heuristic_fallback",
        model_name="heuristic-security-v1",
    )


def _try_transformer_classification(text: str, language: str) -> MLClassification | None:
    loaded_pipeline = _load_transformer_pipeline()
    if loaded_pipeline is None:
        return None

    classifier, task = loaded_pipeline

    settings = get_settings()

    if task == "text-classification":
        try:
            payload = classifier(
                text[: settings.ML_MAX_CLASSIFICATION_CHARS],
                truncation=True,
                top_k=None,
            )
        except TypeError:
            payload = classifier(
                text[: settings.ML_MAX_CLASSIFICATION_CHARS],
                truncation=True,
                return_all_scores=True,
            )
        except Exception as exc:  # pragma: no cover - runtime integration path
            logger.warning("Transformer text-classification failed; switching to fallback: %s", exc)
            return None

        score_rows: list[dict] = []
        if isinstance(payload, list) and payload and isinstance(payload[0], dict):
            score_rows = payload
        elif isinstance(payload, list) and payload and isinstance(payload[0], list):
            score_rows = payload[0]
        elif isinstance(payload, dict):
            score_rows = [payload]

        if not score_rows:
            return None

        mapped_scores = {
            "safe": 0.0,
            "injection": 0.0,
            "pii": 0.0,
        }
        for row in score_rows:
            mapped_label = _map_label(str(row.get("label", "")))
            score = float(row.get("score", 0.0))
            mapped_scores[mapped_label] = max(mapped_scores[mapped_label], score)

        normalized_scores = _normalize_scores(mapped_scores)
        sorted_scores = sorted(normalized_scores.items(), key=lambda item: item[1], reverse=True)
        label = sorted_scores[0][0]
        confidence = round(sorted_scores[0][1], 3)

        reasoning = [
            f"language={language}",
            f"task={task}",
            f"top_label={label}",
            f"runner_up={sorted_scores[1][0]}:{round(sorted_scores[1][1], 3)}",
        ]

        return MLClassification(
            label=label,
            confidence=confidence,
            language=language,
            reasoning=reasoning,
            scores=normalized_scores,
            source="transformer",
            model_name=settings.ML_CLASSIFIER_MODEL,
        )

    candidate_labels = [
        LABEL_DESCRIPTIONS["safe"],
        LABEL_DESCRIPTIONS["injection"],
        LABEL_DESCRIPTIONS["pii"],
    ]

    try:
        payload = classifier(
            text[: settings.ML_MAX_CLASSIFICATION_CHARS],
            candidate_labels,
            multi_label=False,
            hypothesis_template="This message is about {}.",
        )
    except Exception as exc:  # pragma: no cover - runtime integration path
        logger.warning("Transformer zero-shot classification failed; switching to fallback: %s", exc)
        return None

    labels = payload.get("labels", []) if isinstance(payload, dict) else []
    scores = payload.get("scores", []) if isinstance(payload, dict) else []
    if not labels or not scores or len(labels) != len(scores):
        return None

    mapped_scores = {
        "safe": 0.0,
        "injection": 0.0,
        "pii": 0.0,
    }
    for raw_label, score in zip(labels, scores):
        mapped_scores[_map_label(str(raw_label))] = float(score)

    normalized_scores = _normalize_scores(mapped_scores)
    sorted_scores = sorted(normalized_scores.items(), key=lambda item: item[1], reverse=True)
    label = sorted_scores[0][0]
    confidence = round(sorted_scores[0][1], 3)

    reasoning = [
        f"language={language}",
        f"task={task}",
        f"top_label={label}",
        f"runner_up={sorted_scores[1][0]}:{round(sorted_scores[1][1], 3)}",
    ]

    return MLClassification(
        label=label,
        confidence=confidence,
        language=language,
        reasoning=reasoning,
        scores=normalized_scores,
        source="transformer",
        model_name=settings.ML_CLASSIFIER_MODEL,
    )


def classify_user_input(text: str, language_hint: str | None = None) -> MLClassification:
    language = detect_input_language(text, language_hint)

    transformer_result = _try_transformer_classification(text, language.language)
    if transformer_result is not None:
        return transformer_result

    fallback = _heuristic_classification(text, language.language)
    return fallback
