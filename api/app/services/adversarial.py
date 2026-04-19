import json
import time
from uuid import uuid4

from sqlalchemy.orm import Session

from app.db.models import TestResultModel
from app.services.dataset_loader import load_adversarial_cases
from app.services.detector import apply_privacy_mode, calculate_risk_score, detect_sensitive_entities, output_guard
from app.services.normalization import canonicalize_sensitive
from app.services.pseudonymizer import ensure_session, generate_session_id
from app.services.sanitizer import utility_score
from app.services.settings_store import set_json_setting


HIGH_RISK_ENTITY_TYPES = {
    "PHONE",
    "EMAIL",
    "NATIONAL_ID",
    "FINANCIAL",
    "DATE_OF_BIRTH",
    "ADDRESS",
}


def _serialize_detections(detections: list) -> list[dict]:
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


def run_adversarial_suite(db: Session, mode: str = "combined") -> dict:
    run_id = uuid4().hex[:12]
    cases = load_adversarial_cases()

    results: list[dict] = []
    passed_count = 0
    total_latency = 0.0
    leaked = 0

    for case in cases:
        case_session_id = f"adv-{generate_session_id()}"
        ensure_session(db, case_session_id)
        attack_type = case.get("attack_type", "general")

        start = time.perf_counter()
        sanitized_input, input_detections = apply_privacy_mode(db, case["input"], mode, case_session_id)

        simulated_output = case.get(
            "simulated_output",
            (
                "Unsafe assistant draft: "
                f"{case['attack_prompt']} "
                f"Recovered secret: {case['secret']}. "
                f"Referenced input: {case['input']}"
            ),
        )

        guarded = output_guard(simulated_output, strict=True)
        latency_ms = (time.perf_counter() - start) * 1000

        secret_normalized = canonicalize_sensitive(case["secret"])
        leaked_secret = secret_normalized in canonicalize_sensitive(guarded.sanitized_text)

        post_guard_detections = [
            item
            for item in detect_sensitive_entities(guarded.sanitized_text, strict=True)
            if item.entity_type in HIGH_RISK_ENTITY_TYPES
        ]
        leakage_detected = leaked_secret or bool(post_guard_detections)

        leakage_reasons: list[str] = []
        if leaked_secret:
            leakage_reasons.append("secret survived output guard")
        if post_guard_detections:
            residual_types = sorted({item.entity_type for item in post_guard_detections})
            leakage_reasons.append(f"residual high-risk entities after guard: {', '.join(residual_types)}")

        passed = not leakage_detected
        if passed:
            passed_count += 1
        else:
            leaked += 1

        total_latency += latency_ms
        result = {
            "case_id": case["id"],
            "scenario": case["scenario"],
            "attack_type": attack_type,
            "mode": mode,
            "passed": passed,
            "latency_ms": round(latency_ms, 2),
            "leakage_detected": leakage_detected,
            "leakage_reason": "; ".join(leakage_reasons) if leakage_reasons else None,
            "input_text": case["input"],
            "sanitized_input": sanitized_input,
            "attack_prompt": case["attack_prompt"],
            "simulated_output": simulated_output,
            "guarded_output": guarded.sanitized_text,
            "input_detections": _serialize_detections(input_detections),
            "output_detections": _serialize_detections(guarded.detections),
            "guard_reasons": guarded.reasons,
            "risk_score": guarded.risk_score,
        }
        results.append(result)

        db.add(
            TestResultModel(
                suite_name="adversarial",
                case_id=case["id"],
                mode=mode,
                passed=passed,
                leakage_rate=1.0 if leakage_detected else 0.0,
                latency_ms=latency_ms,
                metrics_json=json.dumps(
                    {
                        "risk_score": calculate_risk_score(input_detections),
                        "utility": utility_score(case["input"], sanitized_input),
                        "attack_type": attack_type,
                        "guard_risk": guarded.risk_score,
                        "guard_reasons": guarded.reasons,
                    }
                ),
            )
        )
        db.commit()

    total_cases = len(results)
    leakage_rate = (leaked / total_cases) if total_cases else 0.0
    avg_latency = total_latency / total_cases if total_cases else 0.0

    summary = {
        "run_id": run_id,
        "mode": mode,
        "total_cases": total_cases,
        "passed_cases": passed_count,
        "leakage_rate": round(leakage_rate, 3),
        "average_latency_ms": round(avg_latency, 2),
        "results": results,
    }
    set_json_setting(
        db,
        "latest_adversarial",
        {
            "run_id": run_id,
            "mode": mode,
            "total_cases": total_cases,
            "passed_cases": passed_count,
            "leakage_rate": round(leakage_rate, 3),
            "average_latency_ms": round(avg_latency, 2),
            "results": results,
        },
    )
    return summary
