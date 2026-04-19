import json
import time
from statistics import mean

from sqlalchemy.orm import Session

from app.db.models import TestResultModel
from app.services.dataset_loader import load_conversation_eval_cases, load_entity_eval_cases
from app.services.detector import apply_privacy_mode
from app.services.normalization import canonicalize_sensitive
from app.services.pseudonymizer import ensure_session, generate_session_id
from app.services.sanitizer import utility_score
from app.services.settings_store import set_json_setting

MODES = ["detect_only", "redact", "pseudonymize", "combined"]


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    idx = int(round((len(sorted_values) - 1) * percentile))
    idx = max(0, min(idx, len(sorted_values) - 1))
    return sorted_values[idx]

def _compute_detection_metrics(entity_cases: list[dict], mode: str, db: Session) -> dict:
    tp = fp = fn = 0
    utility_scores: list[float] = []
    latencies: list[float] = []
    leaked_cases = 0

    non_sensitive_cases = 0
    false_positive_cases = 0

    for case in entity_cases:
        session_id = f"eval-{mode}-{generate_session_id()}"
        ensure_session(db, session_id)

        text = case["text"]
        expected = {
            (entity["label"], canonicalize_sensitive(entity["value"]))
            for entity in case.get("entities", [])
        }

        start = time.perf_counter()
        sanitized, detections = apply_privacy_mode(db, text, mode, session_id)
        latency_ms = (time.perf_counter() - start) * 1000

        predicted = {(det.entity_type, canonicalize_sensitive(det.matched_text)) for det in detections}

        tp += len(predicted & expected)
        fp += len(predicted - expected)
        fn += len(expected - predicted)

        if not expected:
            non_sensitive_cases += 1
            if predicted:
                false_positive_cases += 1

        if expected:
            if any(expected_value in canonicalize_sensitive(sanitized) for _, expected_value in expected):
                leaked_cases += 1

        utility_scores.append(utility_score(text, sanitized))
        latencies.append(latency_ms)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    false_positive_rate = (false_positive_cases / non_sensitive_cases) if non_sensitive_cases else 0.0
    leakage_rate = leaked_cases / len(entity_cases) if entity_cases else 0.0

    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "false_positive_rate": round(false_positive_rate, 3),
        "utility": round(mean(utility_scores), 3) if utility_scores else 0.0,
        "leakage_rate": round(leakage_rate, 3),
        "avg_latency_ms": round(mean(latencies), 2) if latencies else 0.0,
        "p50_latency_ms": round(_percentile(latencies, 0.5), 2),
        "p95_latency_ms": round(_percentile(latencies, 0.95), 2),
    }


def _compute_pseudonym_consistency(conversation_cases: list[dict], mode: str, db: Session) -> float:
    if mode not in {"pseudonymize", "combined"}:
        return 0.0

    total_repeats = 0
    consistent_repeats = 0

    for case in conversation_cases:
        session_id = f"eval-conv-{generate_session_id()}"
        ensure_session(db, session_id)

        seen: dict[str, str] = {}
        for turn in case.get("turns", []):
            text = turn["text"]
            _, detections = apply_privacy_mode(db, text, mode, session_id)
            for detection in detections:
                if not detection.placeholder:
                    continue
                canonical = canonicalize_sensitive(detection.matched_text)
                if canonical in seen:
                    total_repeats += 1
                    if seen[canonical] == detection.placeholder:
                        consistent_repeats += 1
                else:
                    seen[canonical] = detection.placeholder

    if total_repeats == 0:
        return 1.0
    return round(consistent_repeats / total_repeats, 3)


def run_evaluation_suite(db: Session) -> dict:
    entity_cases = load_entity_eval_cases()
    conversation_cases = load_conversation_eval_cases()

    mode_comparison: dict[str, dict] = {}

    for mode in MODES:
        metrics = _compute_detection_metrics(entity_cases, mode, db)
        metrics["pseudonym_consistency"] = _compute_pseudonym_consistency(conversation_cases, mode, db)
        mode_comparison[mode] = metrics

        db.add(
            TestResultModel(
                suite_name="evaluation",
                case_id=f"summary:{mode}",
                mode=mode,
                passed=metrics["leakage_rate"] <= 0.2,
                leakage_rate=metrics["leakage_rate"],
                latency_ms=metrics["avg_latency_ms"],
                metrics_json=json.dumps(metrics),
            )
        )
        db.commit()

    summary = {"mode_comparison": mode_comparison}
    set_json_setting(db, "latest_evaluation", summary)
    return summary
