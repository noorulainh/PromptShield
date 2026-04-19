from statistics import mean

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.models import EventModel, SessionModel
from app.services.settings_store import get_json_setting


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    idx = int(round((len(sorted_values) - 1) * percentile))
    idx = max(0, min(idx, len(sorted_values) - 1))
    return round(sorted_values[idx], 2)


def _default_mode_metrics() -> dict:
    return {
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
        "false_positive_rate": 0.0,
        "utility": 0.0,
        "leakage_rate": 0.0,
        "avg_latency_ms": 0.0,
        "p50_latency_ms": 0.0,
        "p95_latency_ms": 0.0,
        "pseudonym_consistency": 0.0,
    }


def get_dashboard_metrics(db: Session) -> dict:
    total_events = db.scalar(select(func.count()).select_from(EventModel)) or 0
    active_sessions = db.scalar(select(func.count()).select_from(SessionModel)) or 0

    events = db.scalars(select(EventModel).order_by(desc(EventModel.created_at)).limit(400)).all()
    latencies = [event.latency_ms for event in events]
    risks = [event.risk_score for event in events]
    processed_events = [event for event in events if event.event_type in {"prompt_process", "conversation_turn"}]

    blocked_count = sum(1 for event in processed_events if event.final_action == "block")
    fallback_count = sum(
        1
        for event in processed_events
        if event.decision_source in {"heuristic_based", "heuristic_fallback"}
    )
    unsafe_count = sum(1 for event in processed_events if event.predicted_label in {"injection", "pii"})

    label_distribution = {
        "safe": sum(1 for event in processed_events if event.predicted_label == "safe"),
        "pii": sum(1 for event in processed_events if event.predicted_label == "pii"),
        "injection": sum(1 for event in processed_events if event.predicted_label == "injection"),
    }

    latest_eval = get_json_setting(db, "latest_evaluation", {"mode_comparison": {}})
    latest_adv = get_json_setting(db, "latest_adversarial", {"leakage_rate": 0.0})

    mode_comparison = latest_eval.get("mode_comparison", {})
    for mode in ["detect_only", "redact", "pseudonymize", "combined"]:
        mode_comparison.setdefault(mode, _default_mode_metrics())

    recent_events = [
        {
            "id": event.id,
            "session_id": event.session_id,
            "event_type": event.event_type,
            "mode": event.mode,
            "risk_score": event.risk_score,
            "latency_ms": event.latency_ms,
            "leakage_detected": event.leakage_detected,
            "summary": event.summary,
            "created_at": event.created_at.isoformat(),
        }
        for event in events[:15]
    ]

    return {
        "total_events": total_events,
        "active_sessions": active_sessions,
        "average_risk": round(mean(risks), 3) if risks else 0.0,
        "leakage_rate": round(float(latest_adv.get("leakage_rate", 0.0)), 3),
        "blocked_rate": round((blocked_count / len(processed_events)), 3) if processed_events else 0.0,
        "fallback_rate": round((fallback_count / len(processed_events)), 3) if processed_events else 0.0,
        "unsafe_rate": round((unsafe_count / len(processed_events)), 3) if processed_events else 0.0,
        "avg_latency_ms": round(mean(latencies), 2) if latencies else 0.0,
        "p50_latency_ms": _percentile(latencies, 0.5),
        "p95_latency_ms": _percentile(latencies, 0.95),
        "label_distribution": label_distribution,
        "mode_comparison": mode_comparison,
        "recent_events": recent_events,
    }


def get_session_metrics(db: Session, session_id: str) -> dict:
    events = db.scalars(
        select(EventModel)
        .where(EventModel.session_id == session_id)
        .order_by(desc(EventModel.created_at))
        .limit(600)
    ).all()

    turn_events = [event for event in events if event.event_type == "conversation_turn"]
    output_events = [event for event in events if event.event_type == "conversation_output"]

    total_turns = len(turn_events)
    if total_turns == 0:
        return {
            "session_id": session_id,
            "has_activity": False,
            "total_turns": 0,
            "blocked_attack_rate": 0.0,
            "leakage_rate": 0.0,
            "fallback_rate": 0.0,
            "avg_latency_ms": 0.0,
            "avg_masked_utility": 1.0,
            "usability_impact": 0.0,
        }

    blocked_attacks = sum(1 for event in turn_events if event.final_action == "block" or event.predicted_label == "injection")
    fallback_count = sum(
        1
        for event in turn_events
        if event.decision_source in {"heuristic_based", "heuristic_fallback"}
    )
    latencies = [event.latency_ms for event in turn_events]

    masked_utilities = [
        event.utility_score
        for event in turn_events
        if event.final_action == "mask" and event.utility_score is not None
    ]
    avg_masked_utility = round(mean(masked_utilities), 3) if masked_utilities else 1.0

    leakage_events = sum(1 for event in output_events if event.leakage_detected)
    leakage_rate = (leakage_events / len(output_events)) if output_events else 0.0

    return {
        "session_id": session_id,
        "has_activity": True,
        "total_turns": total_turns,
        "blocked_attack_rate": round(blocked_attacks / total_turns, 3),
        "leakage_rate": round(leakage_rate, 3),
        "fallback_rate": round(fallback_count / total_turns, 3),
        "avg_latency_ms": round(mean(latencies), 2) if latencies else 0.0,
        "avg_masked_utility": avg_masked_utility,
        "usability_impact": round(max(0.0, 1.0 - avg_masked_utility), 3),
    }
