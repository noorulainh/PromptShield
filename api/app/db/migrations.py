from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine


def ensure_event_metadata_columns(engine: Engine) -> None:
    inspector = inspect(engine)
    if "events" not in inspector.get_table_names():
        return

    existing_columns = {item["name"] for item in inspector.get_columns("events")}
    required_columns = {
        "raw_input_masked": "TEXT",
        "language": "VARCHAR(32)",
        "predicted_label": "VARCHAR(32)",
        "confidence_score": "FLOAT",
        "pii_detected": "BOOLEAN DEFAULT 0",
        "final_action": "VARCHAR(16)",
        "decision_source": "VARCHAR(32)",
        "decision_reasoning": "TEXT",
        "model_name": "VARCHAR(160)",
    }

    with engine.begin() as conn:
        for column_name, column_type in required_columns.items():
            if column_name in existing_columns:
                continue
            conn.execute(text(f"ALTER TABLE events ADD COLUMN {column_name} {column_type}"))
