from sqlalchemy.orm import Session

from app.services.settings_store import DEFAULT_APP_SETTINGS, get_json_setting, set_json_setting


def seed_default_settings(db: Session) -> None:
    existing = get_json_setting(db, "app_settings", None)
    if existing is None:
        set_json_setting(db, "app_settings", DEFAULT_APP_SETTINGS)

    if get_json_setting(db, "latest_evaluation", None) is None:
        set_json_setting(
            db,
            "latest_evaluation",
            {
                "mode_comparison": {
                    "detect_only": {
                        "precision": 0.0,
                        "recall": 0.0,
                        "f1": 0.0,
                        "false_positive_rate": 0.0,
                        "utility": 1.0,
                        "leakage_rate": 1.0,
                        "avg_latency_ms": 0.0,
                        "p50_latency_ms": 0.0,
                        "p95_latency_ms": 0.0,
                        "pseudonym_consistency": 0.0,
                    },
                    "redact": {
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
                    },
                    "pseudonymize": {
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
                    },
                    "combined": {
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
                    },
                }
            },
        )

    if get_json_setting(db, "latest_adversarial", None) is None:
        set_json_setting(db, "latest_adversarial", {"leakage_rate": 0.0, "total_cases": 0, "passed_cases": 0})
